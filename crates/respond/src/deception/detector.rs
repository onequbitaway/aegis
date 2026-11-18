//! The detector for events that touch a honeytoken.

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_contracts::Result;
use aegis_contracts::common::{DetectionId, EntityKind, EntityRef, Severity};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Detector, Verdict};
use aegis_contracts::event::{Event, attr};
use async_trait::async_trait;
use serde_json::json;

use super::{HoneytokenKind, HoneytokenRegistry, Trip, TripMatch};
use crate::names::{entity_label, snake_name};

/// The identifier of [`HoneytokenTripDetector`] and the `rule_id` of its detections.
pub const HONEYTOKEN_DETECTOR_ID: &str = "aegis.deception.honeytoken_trip";

/// A tier 1 detector. It finds each event that touches an active honeytoken.
///
/// A honeytoken has no legitimate use, so each detection has the verdict
/// [`Verdict::Malicious`] and the severity [`Severity::High`] or more. The severity is
/// [`Severity::Critical`] if the event holds the decoy value: the attacker then uses data
/// that it took from the decoy.
///
/// The detection names the actor and the source address as entities. It does not name the
/// decoy as an entity, so a playbook does not act on the decoy. The attributes of the
/// detection name the honeytoken and its placement. They never hold the decoy value.
pub struct HoneytokenTripDetector {
    registry: Arc<HoneytokenRegistry>,
}

impl HoneytokenTripDetector {
    /// Makes a detector for the honeytokens of `registry`.
    #[must_use]
    pub fn new(registry: Arc<HoneytokenRegistry>) -> Self {
        Self { registry }
    }
}

fn technique(trip: &Trip) -> AttackTechnique {
    match (trip.matched, trip.token.kind) {
        (TripMatch::DecoyValue | TripMatch::Actor, _) => {
            AttackTechnique::new("initial-access", "T1078", "Valid Accounts")
        }
        (
            TripMatch::HoneytokenId | TripMatch::Target,
            HoneytokenKind::Secret | HoneytokenKind::Credential,
        ) => AttackTechnique::new("credential-access", "T1552", "Unsecured Credentials"),
        (TripMatch::HoneytokenId | TripMatch::Target, _) => {
            AttackTechnique::new("discovery", "T1087", "Account Discovery")
        }
    }
}

fn detection(trip: &Trip, event: &Event) -> Detection {
    let actor = event.actor.entity();
    let placement = entity_label(&trip.token.placement);
    let how = match trip.matched {
        TripMatch::DecoyValue => "used the decoy value of",
        TripMatch::HoneytokenId | TripMatch::Target => "touched",
        TripMatch::Actor => "operated as",
    };
    let severity = if trip.matched == TripMatch::DecoyValue {
        Severity::Critical
    } else {
        event.severity.max(Severity::High)
    };
    let mut entities = vec![actor.clone()];
    if let Some(ip) = event.actor.ip {
        entities.push(EntityRef::new(EntityKind::IpAddress, ip.to_string()));
    }
    let mut attributes = BTreeMap::new();
    attributes.insert(attr::HONEYTOKEN_ID.to_owned(), json!(trip.token.id));
    attributes.insert("honeytoken_kind".to_owned(), json!(trip.token.kind));
    attributes.insert("match".to_owned(), json!(trip.matched));
    attributes.insert(
        "placement_kind".to_owned(),
        json!(trip.token.placement.kind),
    );
    attributes.insert("placement_id".to_owned(), json!(trip.token.placement.id));
    attributes.insert("event_action".to_owned(), json!(event.action));
    Detection {
        id: DetectionId::new(),
        rule_id: HONEYTOKEN_DETECTOR_ID.to_owned(),
        title: format!("Honeytoken trip at {placement}"),
        description: format!(
            "The {} {how} the honeytoken {}, a decoy at {placement}. A honeytoken has no legitimate use. The event action was {}.",
            entity_label(&actor),
            trip.token.id,
            event.action
        ),
        severity,
        verdict: Verdict::Malicious,
        tier: DetectionTier::Deterministic,
        time: event.time,
        attack: vec![technique(trip)],
        event_ids: vec![event.id],
        entities,
        tenant: event
            .source
            .tenant
            .clone()
            .or_else(|| event.actor.tenant.clone()),
        attributes,
    }
}

#[async_trait]
impl Detector for HoneytokenTripDetector {
    fn id(&self) -> &str {
        HONEYTOKEN_DETECTOR_ID
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Deterministic
    }

    /// Returns one detection for each active honeytoken that the event touches.
    ///
    /// Refer to [`HoneytokenRegistry::trips`] for the ways in which an event touches a
    /// honeytoken.
    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        let trips = self.registry.trips(event);
        for trip in &trips {
            tracing::warn!(
                honeytoken_id = %trip.token.id,
                matched = %snake_name(&trip.matched),
                event_id = %event.id,
                "an event touched a honeytoken"
            );
        }
        Ok(trips.iter().map(|trip| detection(trip, event)).collect())
    }
}
