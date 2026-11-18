//! Integration tests for the deception module: the registry, the detector, and the connector.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use aegis_contracts::Error;
use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionStatus,
};
use aegis_contracts::audit::AuditLog;
use aegis_contracts::common::{EntityKind, EntityRef, Severity};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Detector, Verdict};
use aegis_contracts::event::{Actor, Event, EventClass, Outcome, action, attr};
use aegis_respond::deception::{
    HONEYTOKEN_DETECTOR_ID, HoneytokenStore, MemoryHoneytokenStore, TripMatch, parameter,
};
use aegis_respond::{
    ActionRegistry, Dispatcher, Honeytoken, HoneytokenConnector, HoneytokenKind,
    HoneytokenRegistry, HoneytokenRequest, HoneytokenTripDetector,
};
use aegis_testkit::fixtures::{
    self, ATTACK_LOG_EVENTS, HONEYTOKEN_ID, ROGUE_PRINCIPAL_ID, TENANT, WORKLOAD_IP,
};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, MemoryBus, StaticPolicy};
use serde_json::json;

use common::{request, responder};

/// The secret that the rogue service principal reads in the recorded attack log.
const FIXTURE_SECRET: &str = "kv-prod/legacy-admin-password";

async fn registry() -> Arc<HoneytokenRegistry> {
    Arc::new(
        HoneytokenRegistry::open(Arc::new(MemoryHoneytokenStore::default()))
            .await
            .unwrap(),
    )
}

fn decoy_secret(name: &str) -> HoneytokenRequest {
    HoneytokenRequest::new(
        HoneytokenKind::Secret,
        EntityRef::new(EntityKind::Secret, name).with_tenant(TENANT),
        format!("A decoy secret with the name {name}."),
    )
}

/// Returns the honeytoken event of the recorded attack log, and all other events.
fn fixture_events() -> (Event, Vec<Event>) {
    let (trips, others): (Vec<Event>, Vec<Event>) = fixtures::artex_style_attack()
        .into_iter()
        .partition(|event| event.action == action::HONEYTOKEN_TRIP);
    assert_eq!(trips.len(), 1);
    assert_eq!(others.len(), ATTACK_LOG_EVENTS - 1);
    (trips.into_iter().next().unwrap(), others)
}

/// Makes a successful API call by a user that has nothing to do with a honeytoken.
fn api_call(time_offset_seconds: i64) -> Event {
    Event::new(
        fixtures::base_time() + chrono::Duration::seconds(time_offset_seconds),
        fixtures::source(),
        EventClass::ApiActivity,
        action::API_CALL,
        Actor::new(EntityKind::User, "user-001")
            .with_tenant(TENANT)
            .with_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
    )
    .with_outcome(Outcome::Success)
}

fn only(detections: Vec<Detection>) -> Detection {
    assert_eq!(detections.len(), 1, "{detections:?}");
    detections.into_iter().next().unwrap()
}

#[tokio::test]
async fn issue_makes_a_random_identifier_and_a_random_decoy_value() {
    let store = Arc::new(MemoryHoneytokenStore::default());
    let registry = HoneytokenRegistry::open(store.clone()).await.unwrap();

    let first = registry
        .issue(decoy_secret("kv-prod/decoy-a").issued_by("deception"))
        .await
        .unwrap();
    let second = registry
        .issue(decoy_secret("kv-prod/decoy-b"))
        .await
        .unwrap();

    for token in [&first, &second] {
        assert_eq!(token.id.len(), 35, "{}", token.id);
        assert!(token.id.starts_with("ht-"), "{}", token.id);
        assert!(token.id[3..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(token.decoy_value.expose().len(), 40);
        assert!(
            token
                .decoy_value
                .expose()
                .chars()
                .all(|c| c.is_ascii_alphanumeric())
        );
        assert!(token.is_active());
        assert_eq!(token.retired_at, None);
        assert_eq!(token.action_id, None);
        assert_eq!(token.kind, HoneytokenKind::Secret);
        assert!(
            !format!("{token:?}").contains(token.decoy_value.expose()),
            "the Debug output shows the decoy value"
        );
    }
    assert_ne!(first.id, second.id);
    assert_ne!(first.decoy_value, second.decoy_value);
    assert_eq!(
        first.placement,
        EntityRef::new(EntityKind::Secret, "kv-prod/decoy-a").with_tenant(TENANT)
    );
    assert_eq!(
        first.description,
        "A decoy secret with the name kv-prod/decoy-a."
    );
    assert_eq!(first.issued_by, "deception");
    assert_eq!(second.issued_by, "operator");

    assert_eq!(
        registry.list().await.unwrap(),
        [first.clone(), second.clone()]
    );
    assert_eq!(registry.active(), [first.clone(), second.clone()]);
    assert_eq!(
        registry.get(&second.id).await.unwrap(),
        Some(second.clone())
    );
    assert_eq!(registry.get("ht-unknown").await.unwrap(), None);
    // The registry wrote both honeytokens to the store.
    assert_eq!(store.list().await.unwrap(), [first, second]);
}

#[tokio::test]
async fn issue_rejects_input_that_is_not_valid() {
    let registry = registry().await;
    let invalid = |result: aegis_contracts::Result<Honeytoken>| match result {
        Err(Error::InvalidInput(message)) => message,
        other => panic!("expected an input error, found {other:?}"),
    };
    let token = registry
        .issue(decoy_secret("kv-prod/decoy").with_id("canary-7"))
        .await
        .unwrap();
    assert_eq!(token.id, "canary-7");

    assert_eq!(
        invalid(
            registry
                .issue(decoy_secret("kv-prod/other").with_id("canary-7"))
                .await
        ),
        "a honeytoken with the identifier canary-7 already exists"
    );
    assert_eq!(
        invalid(registry.issue(decoy_secret("kv-prod/decoy")).await),
        "an active honeytoken already has the placement secret kv-prod/decoy"
    );
    assert_eq!(
        invalid(registry.issue(decoy_secret("  ")).await),
        "the placement of a honeytoken must have an identifier"
    );
    let mut no_description = decoy_secret("kv-prod/other");
    no_description.description = " ".to_owned();
    assert_eq!(
        invalid(registry.issue(no_description).await),
        "the description of a honeytoken must have 1 to 500 characters"
    );
    let mut long_description = decoy_secret("kv-prod/other");
    long_description.description = "d".repeat(501);
    assert_eq!(
        invalid(registry.issue(long_description).await),
        "the description of a honeytoken must have 1 to 500 characters"
    );
    assert_eq!(
        invalid(
            registry
                .issue(decoy_secret("kv-prod/other").with_id("bad\nid"))
                .await
        ),
        "the identifier of a honeytoken must have 1 to 128 characters and no control characters"
    );
    assert_eq!(registry.list().await.unwrap(), [token]);

    // A retired honeytoken frees its placement, but not its identifier.
    registry.retire("canary-7").await.unwrap();
    let replacement = registry.issue(decoy_secret("kv-prod/decoy")).await.unwrap();
    assert_eq!(registry.active(), [replacement]);
    assert_eq!(
        invalid(
            registry
                .issue(decoy_secret("kv-prod/third").with_id("canary-7"))
                .await
        ),
        "a honeytoken with the identifier canary-7 already exists"
    );
}

#[tokio::test]
async fn the_fixture_honeytoken_event_trips_on_the_honeytoken_id_attribute() {
    let registry = registry().await;
    // The placement is not the secret of the fixture, so only the attribute can match.
    let token = registry
        .issue(decoy_secret("kv-prod/other-decoy").with_id(HONEYTOKEN_ID))
        .await
        .unwrap();
    let detector = HoneytokenTripDetector::new(registry.clone());
    assert_eq!(detector.id(), HONEYTOKEN_DETECTOR_ID);
    assert_eq!(detector.id(), "aegis.deception.honeytoken_trip");
    assert_eq!(detector.tier(), DetectionTier::Deterministic);
    let (trip, _) = fixture_events();
    assert_eq!(trip.attribute_str(attr::HONEYTOKEN_ID), Some(HONEYTOKEN_ID));

    let detection = only(detector.inspect(&trip).await.unwrap());

    assert_eq!(detection.rule_id, HONEYTOKEN_DETECTOR_ID);
    assert_eq!(detection.verdict, Verdict::Malicious);
    assert_eq!(detection.severity, Severity::High);
    assert_eq!(detection.tier, DetectionTier::Deterministic);
    assert_eq!(detection.time, trip.time);
    assert_eq!(detection.event_ids, [trip.id]);
    assert_eq!(detection.tenant.as_deref(), Some(TENANT));
    assert_eq!(
        detection.entities,
        [
            EntityRef::new(EntityKind::ServicePrincipal, ROGUE_PRINCIPAL_ID)
                .with_name("Sync Helper")
                .with_tenant(TENANT),
            EntityRef::new(EntityKind::IpAddress, WORKLOAD_IP.to_string()),
        ]
    );
    assert_eq!(
        detection.attack,
        [AttackTechnique::new(
            "credential-access",
            "T1552",
            "Unsecured Credentials"
        )]
    );
    assert_eq!(
        detection.attributes,
        BTreeMap::from([
            ("event_action".to_owned(), json!("honeytoken.trip")),
            ("honeytoken_id".to_owned(), json!(HONEYTOKEN_ID)),
            ("honeytoken_kind".to_owned(), json!("secret")),
            ("match".to_owned(), json!("honeytoken_id")),
            ("placement_id".to_owned(), json!("kv-prod/other-decoy")),
            ("placement_kind".to_owned(), json!("secret")),
        ])
    );
    assert_eq!(
        detection.title,
        "Honeytoken trip at secret kv-prod/other-decoy"
    );
    let trips = registry.trips(&trip);
    assert_eq!(trips.len(), 1);
    assert_eq!(trips[0].token, token);
    assert_eq!(trips[0].matched, TripMatch::HoneytokenId);
}

#[tokio::test]
async fn the_fixture_honeytoken_event_trips_on_the_target() {
    let (trip, _) = fixture_events();
    let target = trip.target.clone().unwrap();
    assert_eq!(
        target,
        EntityRef::new(EntityKind::Secret, FIXTURE_SECRET).with_tenant(TENANT)
    );

    // The target of the event is the placement of the honeytoken.
    let by_placement = registry().await;
    let token = by_placement
        .issue(decoy_secret(FIXTURE_SECRET))
        .await
        .unwrap();
    assert_ne!(token.id, HONEYTOKEN_ID);
    let detection = only(
        HoneytokenTripDetector::new(by_placement)
            .inspect(&trip)
            .await
            .unwrap(),
    );
    assert_eq!(detection.verdict, Verdict::Malicious);
    assert_eq!(detection.severity, Severity::High);
    assert_eq!(detection.attributes["match"], "target");
    assert_eq!(detection.attributes["honeytoken_id"], json!(token.id));

    // The identifier of the target is the identifier of the honeytoken.
    let by_id = registry().await;
    let token = by_id
        .issue(decoy_secret("kv-prod/other-decoy"))
        .await
        .unwrap();
    let mut event = api_call(60);
    event.target = Some(EntityRef::new(EntityKind::Resource, token.id.clone()));
    let detection = only(
        HoneytokenTripDetector::new(by_id)
            .inspect(&event)
            .await
            .unwrap(),
    );
    assert_eq!(detection.attributes["match"], "target");
    assert_eq!(detection.severity, Severity::High);

    // The same secret name in a different tenant is a different secret.
    let other_tenant = registry().await;
    other_tenant
        .issue(HoneytokenRequest::new(
            HoneytokenKind::Secret,
            EntityRef::new(EntityKind::Secret, FIXTURE_SECRET).with_tenant("tenant-fabrikam"),
            "A decoy secret in a different tenant.",
        ))
        .await
        .unwrap();
    let detections = HoneytokenTripDetector::new(other_tenant)
        .inspect(&trip)
        .await
        .unwrap();
    assert_eq!(detections, []);
}

#[tokio::test]
async fn a_decoy_value_in_the_attributes_is_a_critical_trip() {
    let registry = registry().await;
    let token = registry
        .issue(HoneytokenRequest::new(
            HoneytokenKind::Credential,
            EntityRef::new(EntityKind::Resource, "repo/deploy/.env"),
            "A decoy API key in the deployment repository.",
        ))
        .await
        .unwrap();
    let decoy = token.decoy_value.expose().to_owned();
    let detector = HoneytokenTripDetector::new(registry);
    let attributes = [
        json!(decoy),
        json!(format!("Bearer {decoy}")),
        json!(["first", { "authorization": format!("Bearer {decoy}") }]),
    ];

    for value in attributes {
        let event = api_call(120).with_attribute("request_headers", value.clone());

        let detection = only(detector.inspect(&event).await.unwrap());

        assert_eq!(detection.severity, Severity::Critical, "{value}");
        assert_eq!(detection.verdict, Verdict::Malicious, "{value}");
        assert_eq!(detection.attributes["match"], "decoy_value", "{value}");
        assert_eq!(
            detection.attack,
            [AttackTechnique::new(
                "initial-access",
                "T1078",
                "Valid Accounts"
            )],
            "{value}"
        );
        assert_eq!(
            detection.entities,
            [
                EntityRef::new(EntityKind::User, "user-001").with_tenant(TENANT),
                EntityRef::new(EntityKind::IpAddress, "198.51.100.10"),
            ],
            "{value}"
        );
        let text = serde_json::to_string(&detection).unwrap();
        assert!(
            !text.contains(&decoy),
            "the detection holds the decoy value"
        );
    }

    // A different random value of the same form does not trip.
    let other = "A".repeat(decoy.len());
    let event = api_call(180).with_attribute("request_headers", format!("Bearer {other}"));
    assert_eq!(detector.inspect(&event).await.unwrap(), []);
}

#[tokio::test]
async fn an_actor_that_is_a_decoy_identity_trips_with_a_severity_of_high_or_more() {
    let registry = registry().await;
    registry
        .issue(HoneytokenRequest::new(
            HoneytokenKind::Application,
            EntityRef::new(EntityKind::ServicePrincipal, "sp-decoy-admin-tool"),
            "A decoy application with no legitimate use.",
        ))
        .await
        .unwrap();
    let detector = HoneytokenTripDetector::new(registry);
    let sign_in = |severity: Severity| {
        Event::new(
            fixtures::base_time(),
            fixtures::source(),
            EventClass::Authentication,
            action::SIGN_IN,
            Actor::new(EntityKind::ServicePrincipal, "sp-decoy-admin-tool"),
        )
        .with_severity(severity)
    };

    for (event_severity, expected) in [
        (Severity::Informational, Severity::High),
        (Severity::Medium, Severity::High),
        (Severity::High, Severity::High),
        (Severity::Critical, Severity::Critical),
    ] {
        let detection = only(detector.inspect(&sign_in(event_severity)).await.unwrap());
        assert_eq!(detection.severity, expected, "{event_severity:?}");
        assert_eq!(detection.verdict, Verdict::Malicious);
        assert_eq!(detection.attributes["match"], "actor");
        // The event has no address, so the actor is the only entity.
        assert_eq!(
            detection.entities,
            [EntityRef::new(
                EntityKind::ServicePrincipal,
                "sp-decoy-admin-tool"
            )]
        );
    }
}

#[tokio::test]
async fn a_retired_honeytoken_does_not_trip() {
    let registry = registry().await;
    let token = registry
        .issue(decoy_secret(FIXTURE_SECRET).with_id(HONEYTOKEN_ID))
        .await
        .unwrap();
    let detector = HoneytokenTripDetector::new(registry.clone());
    let (trip, _) = fixture_events();
    assert_eq!(detector.inspect(&trip).await.unwrap().len(), 1);

    let retired = registry.retire(HONEYTOKEN_ID).await.unwrap();

    assert_eq!(detector.inspect(&trip).await.unwrap(), []);
    assert!(!retired.is_active());
    let retired_at = retired.retired_at.unwrap();
    assert!(retired_at >= token.issued_at);
    assert_eq!(registry.active(), []);
    // The list keeps the retired honeytoken as a record.
    assert_eq!(
        registry.list().await.unwrap(),
        std::slice::from_ref(&retired)
    );
    assert_eq!(retired.decoy_value, token.decoy_value);

    // A second retirement changes nothing.
    let again = registry.retire(HONEYTOKEN_ID).await.unwrap();
    assert_eq!(again.retired_at, Some(retired_at));
    assert_eq!(registry.list().await.unwrap(), [retired]);

    let unknown = registry.retire("ht-unknown").await.unwrap_err();
    assert!(
        matches!(&unknown, Error::NotFound(message) if message == "honeytoken ht-unknown"),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn events_that_do_not_touch_a_honeytoken_do_not_trip() {
    let registry = registry().await;
    registry
        .issue(decoy_secret(FIXTURE_SECRET).with_id(HONEYTOKEN_ID))
        .await
        .unwrap();
    registry
        .issue(HoneytokenRequest::new(
            HoneytokenKind::Application,
            EntityRef::new(EntityKind::ServicePrincipal, "sp-decoy-admin-tool"),
            "A decoy application with no legitimate use.",
        ))
        .await
        .unwrap();
    let detector = HoneytokenTripDetector::new(registry);
    let (trip, others) = fixture_events();

    let mut inspected = 0;
    for event in &others {
        let detections = detector.inspect(event).await.unwrap();
        assert_eq!(detections, [], "{} {}", event.action, event.id);
        inspected += 1;
    }
    assert_eq!(inspected, 647);
    // The same detector does trip on the honeytoken event of the log.
    assert_eq!(detector.inspect(&trip).await.unwrap().len(), 1);

    // An event that names a honeytoken that the registry does not know does not trip.
    let unknown =
        api_call(240).with_attribute(attr::HONEYTOKEN_ID, "honeytoken-of-a-different-system");
    assert_eq!(detector.inspect(&unknown).await.unwrap(), []);
}

#[tokio::test]
async fn a_registry_reads_the_active_honeytokens_from_its_store() {
    let store = Arc::new(MemoryHoneytokenStore::default());
    let writer = HoneytokenRegistry::open(store.clone()).await.unwrap();
    writer
        .issue(decoy_secret(FIXTURE_SECRET).with_id(HONEYTOKEN_ID))
        .await
        .unwrap();
    writer
        .issue(decoy_secret("kv-prod/old-decoy").with_id("canary-old"))
        .await
        .unwrap();
    writer.retire("canary-old").await.unwrap();

    // A second process opens the same store.
    let reader = Arc::new(HoneytokenRegistry::open(store.clone()).await.unwrap());
    assert_eq!(
        reader
            .active()
            .iter()
            .map(|token| token.id.as_str())
            .collect::<Vec<_>>(),
        [HONEYTOKEN_ID]
    );
    assert_eq!(reader.list().await.unwrap().len(), 2);
    let (trip, _) = fixture_events();
    let detector = HoneytokenTripDetector::new(reader.clone());
    assert_eq!(detector.inspect(&trip).await.unwrap().len(), 1);

    // The reader sees a later change of the store after a refresh.
    writer.retire(HONEYTOKEN_ID).await.unwrap();
    assert_eq!(detector.inspect(&trip).await.unwrap().len(), 1);
    assert_eq!(reader.refresh().await.unwrap(), 0);
    assert_eq!(detector.inspect(&trip).await.unwrap(), []);
}

/// A dispatcher that permits each action, with the honeytoken connector.
struct Deception {
    dispatcher: Dispatcher,
    registry: Arc<HoneytokenRegistry>,
    connector: Arc<HoneytokenConnector>,
    audit: Arc<MemoryAuditLog>,
    bus: Arc<MemoryBus>,
}

async fn deception(dry_run: bool) -> Deception {
    let registry = registry().await;
    let connector = Arc::new(HoneytokenConnector::new("deception", registry.clone()));
    let mut actions = ActionRegistry::new();
    actions.register(connector.clone()).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let bus = Arc::new(MemoryBus::default());
    let dispatcher = Dispatcher::builder(
        Arc::new(actions),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .bus(bus.clone())
    .dry_run(dry_run)
    .build();
    Deception {
        dispatcher,
        registry,
        connector,
        audit,
        bus,
    }
}

fn deploy_request() -> ActionRequest {
    let mut deploy = request(
        ActionKind::DeployHoneytoken,
        EntityRef::new(EntityKind::Secret, "kv-prod/decoy-admin-password").with_tenant(TENANT),
    );
    deploy.requested_by = "deception".to_owned();
    deploy.reason = "Plant a decoy admin password in the production vault.".to_owned();
    deploy
}

#[tokio::test]
async fn deploy_honeytoken_issues_a_token_and_keeps_the_decoy_value_out_of_the_records() {
    let rig = deception(false).await;
    let mut deploy = deploy_request();
    deploy
        .parameters
        .insert(parameter::KIND.to_owned(), json!("credential"));

    let disposition = rig
        .dispatcher
        .dispatch(deploy.clone(), &responder())
        .await
        .unwrap();

    let ActionDisposition::Executed(outcome) = &disposition else {
        panic!("expected an executed action, found {disposition:?}");
    };
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.connector, "deception");
    assert!(outcome.reversible);
    let tokens = rig.registry.list().await.unwrap();
    assert_eq!(tokens.len(), 1);
    let token = &tokens[0];
    assert_eq!(outcome.details["honeytoken_id"], json!(token.id));
    assert_eq!(outcome.details["kind"], "credential");
    assert_eq!(outcome.details["placement"], json!(deploy.target));
    assert_eq!(token.kind, HoneytokenKind::Credential);
    assert_eq!(token.placement, deploy.target);
    assert_eq!(
        token.description,
        "Plant a decoy admin password in the production vault."
    );
    assert_eq!(token.issued_by, "deception");
    assert_eq!(token.action_id, Some(deploy.id));
    assert!(token.is_active());

    // The decoy value is only in the registry.
    let decoy = token.decoy_value.expose();
    assert_eq!(decoy.len(), 40);
    assert!(!serde_json::to_string(outcome).unwrap().contains(decoy));
    let records = rig.audit.records();
    assert_eq!(records.len(), 3);
    assert!(!serde_json::to_string(&records).unwrap().contains(decoy));
    let messages = rig.bus.published();
    assert_eq!(messages.len(), 1);
    assert!(
        !String::from_utf8(messages[0].payload.clone())
            .unwrap()
            .contains(decoy)
    );
    assert!(rig.audit.verify().await.unwrap().valid);

    // An event on the placement now trips the detector.
    let mut read = api_call(300);
    read.target = Some(deploy.target.clone());
    let detection = only(
        HoneytokenTripDetector::new(rig.registry.clone())
            .inspect(&read)
            .await
            .unwrap(),
    );
    assert_eq!(detection.attributes["honeytoken_id"], json!(token.id));
    assert_eq!(detection.attributes["honeytoken_kind"], "credential");
}

#[tokio::test]
async fn a_dry_run_issues_no_honeytoken() {
    let rig = deception(true).await;

    let disposition = rig
        .dispatcher
        .dispatch(deploy_request(), &responder())
        .await
        .unwrap();

    let ActionDisposition::Executed(outcome) = &disposition else {
        panic!("expected an executed action, found {disposition:?}");
    };
    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert_eq!(
        outcome.message,
        "Would issue a honeytoken for the placement secret kv-prod/decoy-admin-password. This was a dry run. Nothing changed."
    );
    assert_eq!(outcome.details["kind"], "secret");
    assert_eq!(rig.registry.list().await.unwrap(), []);
    assert_eq!(rig.registry.active(), []);
    assert_eq!(rig.audit.records()[2].payload["dry_run"], true);
}

#[tokio::test]
async fn revert_retires_the_honeytoken_of_the_same_request() {
    let rig = deception(false).await;
    let deploy = deploy_request();
    let other = {
        let mut other = deploy_request();
        other.target = EntityRef::new(EntityKind::User, "decoy-admin@contoso.example");
        other
    };
    rig.connector.execute(&deploy).await.unwrap();
    rig.connector.execute(&other).await.unwrap();
    assert_eq!(rig.registry.active().len(), 2);

    // A dry run of the revert changes nothing.
    let mut simulated = deploy.clone();
    simulated.dry_run = true;
    let outcome = rig.connector.revert(&simulated).await.unwrap();
    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert_eq!(rig.registry.active().len(), 2);

    let outcome = rig.connector.revert(&deploy).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Succeeded);
    let active = rig.registry.active();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].action_id, Some(other.id));
    assert_eq!(active[0].kind, HoneytokenKind::User);
    let all = rig.registry.list().await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(outcome.details["honeytoken_id"], json!(all[0].id));
    assert!(all[0].retired_at.is_some());

    let again = rig.connector.revert(&deploy).await.unwrap_err();
    assert!(
        matches!(
            &again,
            Error::NotFound(message)
                if message == &format!("no active honeytoken comes from the action {}", deploy.id)
        ),
        "{again:?}"
    );
}

#[tokio::test]
async fn the_honeytoken_connector_rejects_requests_that_are_not_valid() {
    let rig = deception(false).await;
    let info = rig.connector.info();
    assert_eq!(
        (
            info.name.as_str(),
            info.vendor.as_str(),
            info.product.as_str()
        ),
        ("deception", "aegis", "deception")
    );
    assert_eq!(
        rig.connector.supported_actions(),
        [ActionKind::DeployHoneytoken]
    );

    let mut bad_kind = deploy_request();
    bad_kind
        .parameters
        .insert(parameter::KIND.to_owned(), json!("backdoor"));
    let error = rig.connector.execute(&bad_kind).await.unwrap_err();
    assert!(
        matches!(
            &error,
            Error::InvalidInput(message)
                if message == "the parameter kind must be secret, credential, application, user, or other"
        ),
        "{error:?}"
    );

    let mut bad_id = deploy_request();
    bad_id.parameters.insert(parameter::ID.to_owned(), json!(7));
    let error = rig.connector.execute(&bad_id).await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message == "the parameter id must be a string"),
        "{error:?}"
    );

    let block = request(
        ActionKind::BlockIp,
        EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
    );
    for error in [
        rig.connector.execute(&block).await.unwrap_err(),
        rig.connector.revert(&block).await.unwrap_err(),
    ] {
        assert!(
            matches!(
                &error,
                Error::Unsupported(message)
                    if message == "connector deception does not support the action block_ip"
            ),
            "{error:?}"
        );
    }
    assert_eq!(rig.registry.list().await.unwrap(), []);

    // The identifier and the description can come from the parameters.
    let mut named = deploy_request();
    named
        .parameters
        .insert(parameter::ID.to_owned(), json!(HONEYTOKEN_ID));
    named.parameters.insert(
        parameter::DESCRIPTION.to_owned(),
        json!("The decoy admin password of the legacy vault."),
    );
    rig.connector.execute(&named).await.unwrap();
    let token = rig.registry.get(HONEYTOKEN_ID).await.unwrap().unwrap();
    assert_eq!(
        token.description,
        "The decoy admin password of the legacy vault."
    );
    assert_eq!(token.kind, HoneytokenKind::Secret);
}
