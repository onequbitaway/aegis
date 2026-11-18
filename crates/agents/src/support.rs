//! Helpers that the agents share: incident merge, timeline entries, evidence links, and
//! compact views of an incident for a prompt.

use aegis_contracts::common::{EntityRef, EvidenceKind, EvidenceRef, IncidentId};
use aegis_contracts::detection::{Detection, Verdict};
use aegis_contracts::event::attr;
use aegis_contracts::graph::NodeId;
use aegis_contracts::incident::{Incident, IncidentStatus, TimelineEntry};
use aegis_contracts::{AgentContext, AgentRole, Error, Result};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use crate::prompt::truncate;

/// The note on the evidence link that the Deception agent writes for a honeytoken trip.
pub(crate) const HONEYTOKEN_TRIP_NOTE: &str = "honeytoken_trip";
/// The maximum number of evidence links that one record gets from one incident.
pub(crate) const MAX_EVIDENCE_LINKS: usize = 64;
/// The maximum number of characters of untrusted text in one timeline entry or note.
pub(crate) const MAX_TEXT_CHARS: usize = 600;
const MAX_VIEW_DETECTIONS: usize = 40;
const MAX_VIEW_TIMELINE: usize = 20;

/// Returns the serde name of a unit variant, for example `service_principal`.
pub(crate) fn token<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_owned(),
    }
}

/// Returns a short name for an entity, for example `service_principal sp-1`.
pub(crate) fn entity_label(entity: &EntityRef) -> String {
    format!("{} {}", token(&entity.kind), truncate(&entity.id, 120))
}

/// Returns `true` if the two references address the same entity.
pub(crate) fn same_entity(left: &EntityRef, right: &EntityRef) -> bool {
    left.kind == right.kind && left.id == right.id
}

/// What a merge added to the stored incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct MergeDelta {
    /// `true` if the store had no incident with this identifier.
    pub is_new: bool,
    /// The number of detections that the store did not have.
    pub new_detections: usize,
    /// `true` if the merge changed the stored incident.
    pub changed: bool,
}

/// Merges `incoming` into `stored`.
///
/// The stored incident keeps its status, its summary, and its title, because the agents
/// wrote them. Detections, entities, techniques, and timeline entries are the union of the
/// two incidents. The severity is the larger one.
pub(crate) fn merge(mut stored: Incident, incoming: &Incident) -> (Incident, MergeDelta) {
    let mut delta = MergeDelta::default();
    for detection in &incoming.detections {
        if !stored
            .detections
            .iter()
            .any(|known| known.id == detection.id)
        {
            stored.detections.push(detection.clone());
            delta.new_detections += 1;
            delta.changed = true;
        }
    }
    for entity in &incoming.entities {
        if !stored
            .entities
            .iter()
            .any(|known| same_entity(known, entity))
        {
            stored.entities.push(entity.clone());
            delta.changed = true;
        }
    }
    for technique in &incoming.attack {
        if !stored.attack.contains(technique) {
            stored.attack.push(technique.clone());
            delta.changed = true;
        }
    }
    for entry in &incoming.timeline {
        if !stored.timeline.contains(entry) {
            stored.timeline.push(entry.clone());
            delta.changed = true;
        }
    }
    if incoming.severity > stored.severity {
        stored.severity = incoming.severity;
        delta.changed = true;
    }
    if stored.tenant.is_none() && incoming.tenant.is_some() {
        stored.tenant.clone_from(&incoming.tenant);
        delta.changed = true;
    }
    if stored.summary.is_empty() && !incoming.summary.is_empty() {
        stored.summary.clone_from(&incoming.summary);
        delta.changed = true;
    }
    if delta.changed {
        stored.timeline.sort_by_key(|entry| entry.time);
        stored.updated_at = stored.updated_at.max(incoming.updated_at);
    }
    (stored, delta)
}

/// Returns the present state of `incoming`: the stored incident with the new data of
/// `incoming`, or `incoming` if the store has no such incident.
pub(crate) async fn current(
    context: &AgentContext,
    incoming: &Incident,
) -> Result<(Incident, MergeDelta)> {
    match context.incidents.get(incoming.id).await? {
        Some(stored) => Ok(merge(stored, incoming)),
        None => Ok((
            incoming.clone(),
            MergeDelta {
                is_new: true,
                new_detections: incoming.detections.len(),
                changed: true,
            },
        )),
    }
}

/// Reads an incident from the store. A missing incident gives [`Error::NotFound`].
pub(crate) async fn by_id(context: &AgentContext, id: IncidentId) -> Result<Incident> {
    context
        .incidents
        .get(id)
        .await?
        .ok_or_else(|| Error::NotFound(format!("incident {id}")))
}

/// Returns the evidence links for a decision about `incident`: the incident and its
/// detections.
pub(crate) fn evidence(incident: &Incident) -> Vec<EvidenceRef> {
    let mut links = vec![EvidenceRef::new(EvidenceKind::Incident, incident.id)];
    links.extend(
        incident
            .detections
            .iter()
            .take(MAX_EVIDENCE_LINKS - 1)
            .map(|detection| {
                EvidenceRef::new(EvidenceKind::Detection, detection.id)
                    .with_note(truncate(&detection.rule_id, 120))
            }),
    );
    links
}

/// Adds one entry to the timeline of `incident` and keeps the timeline in time order.
pub(crate) fn add_timeline(
    incident: &mut Incident,
    author: &AgentRole,
    description: impl Into<String>,
    evidence: Vec<EvidenceRef>,
) {
    let now = Utc::now();
    incident.timeline.push(TimelineEntry {
        time: now,
        author: author.token().to_owned(),
        description: description.into(),
        evidence,
    });
    incident.timeline.sort_by_key(|entry| entry.time);
    incident.updated_at = incident.updated_at.max(now);
}

/// Adds one entry with the evidence links of the incident and its detections.
pub(crate) fn add_entry(
    incident: &mut Incident,
    author: &AgentRole,
    description: impl Into<String>,
) {
    let links = evidence(incident);
    add_timeline(incident, author, description, links);
}

/// Returns the last timeline entry that `author` wrote.
pub(crate) fn last_entry_by<'a>(
    incident: &'a Incident,
    author: &AgentRole,
) -> Option<&'a TimelineEntry> {
    incident
        .timeline
        .iter()
        .rev()
        .find(|entry| entry.author == author.token())
}

/// Returns the detections that describe possible attack activity.
pub(crate) fn active_detections(incident: &Incident) -> impl Iterator<Item = &Detection> {
    incident
        .detections
        .iter()
        .filter(|detection| detection.verdict != Verdict::Benign)
}

/// Returns the entities of the incident and of its detections that are not benign, with
/// no duplicates.
pub(crate) fn involved_entities(incident: &Incident) -> Vec<EntityRef> {
    let mut entities: Vec<EntityRef> = Vec::new();
    let from_detections = active_detections(incident).flat_map(|detection| &detection.entities);
    for entity in incident.entities.iter().chain(from_detections) {
        if !entities.iter().any(|known| same_entity(known, entity)) {
            entities.push(entity.clone());
        }
    }
    entities
}

/// Returns `true` if a deterministic detector gave the verdict "malicious".
pub(crate) fn has_malicious_detection(incident: &Incident) -> bool {
    incident
        .detections
        .iter()
        .any(|detection| detection.verdict == Verdict::Malicious)
}

/// Returns `true` if the incident has the record of a honeytoken trip.
///
/// A honeytoken has no legitimate use. A trip is thus a deterministic sign of an attack.
pub(crate) fn has_honeytoken_trip(incident: &Incident) -> bool {
    let in_detections = active_detections(incident)
        .any(|detection| detection.attributes.contains_key(attr::HONEYTOKEN_ID));
    let in_timeline = incident.timeline.iter().any(|entry| {
        entry.author == AgentRole::Deception.token()
            && entry
                .evidence
                .iter()
                .any(|link| link.note.as_deref() == Some(HONEYTOKEN_TRIP_NOTE))
    });
    in_detections || in_timeline
}

/// Returns `true` if the agents can still work on an incident in this state.
pub(crate) fn is_active(status: IncidentStatus) -> bool {
    matches!(
        status,
        IncidentStatus::Open | IncidentStatus::Investigating | IncidentStatus::Contained
    )
}

/// Returns a compact JSON view of an incident for a data section of a prompt.
///
/// The view has no event identifiers and no raw records. All text in it is untrusted.
pub(crate) fn incident_view(incident: &Incident) -> Value {
    let detections: Vec<Value> = incident
        .detections
        .iter()
        .take(MAX_VIEW_DETECTIONS)
        .map(|detection| {
            json!({
                "id": detection.id,
                "rule_id": detection.rule_id,
                "title": detection.title,
                "description": detection.description,
                "severity": detection.severity,
                "verdict": detection.verdict,
                "tier": detection.tier,
                "time": detection.time,
                "techniques": detection
                    .attack
                    .iter()
                    .map(|technique| technique.technique_id.as_str())
                    .collect::<Vec<_>>(),
                "entities": detection
                    .entities
                    .iter()
                    .map(|entity| NodeId::for_entity(entity).0)
                    .collect::<Vec<_>>(),
                "event_count": detection.event_ids.len(),
                "attributes": detection.attributes,
            })
        })
        .collect();
    let first_timeline = incident.timeline.len().saturating_sub(MAX_VIEW_TIMELINE);
    let timeline: Vec<Value> = incident
        .timeline
        .iter()
        .skip(first_timeline)
        .map(|entry| {
            json!({
                "time": entry.time,
                "author": entry.author,
                "description": entry.description,
            })
        })
        .collect();
    json!({
        "id": incident.id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "status": incident.status,
        "tenant": incident.tenant,
        "created_at": incident.created_at,
        "entities": incident
            .entities
            .iter()
            .map(|entity| {
                json!({
                    "node": NodeId::for_entity(entity).0,
                    "kind": entity.kind,
                    "id": entity.id,
                    "name": entity.name,
                    "tenant": entity.tenant,
                })
            })
            .collect::<Vec<_>>(),
        "techniques": incident.attack,
        "detection_count": incident.detections.len(),
        "detections": detections,
        "timeline": timeline,
    })
}

/// Makes untrusted text safe for a timeline entry or an audit note: one line with a
/// maximum length.
pub(crate) fn one_line(text: &str) -> String {
    let flat: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    truncate(&flat, MAX_TEXT_CHARS)
}

#[cfg(test)]
pub(crate) mod testing {
    //! Test data that the unit tests of the agents share.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeMap;

    use aegis_contracts::common::{DetectionId, EntityKind, EntityRef, IncidentId, Severity};
    use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
    use aegis_contracts::incident::{Incident, IncidentStatus};
    use aegis_contracts::{AgentInput, AgentRole, AgentTask};
    use aegis_testkit::fixtures;

    /// The address of the password spray.
    pub(crate) fn spray_ip() -> EntityRef {
        EntityRef::new(EntityKind::IpAddress, fixtures::SPRAY_IP.to_string())
    }

    /// The user whose password the spray found.
    pub(crate) fn victim() -> EntityRef {
        EntityRef::new(EntityKind::User, fixtures::VICTIM_USER_ID)
            .with_name("dana@contoso.example")
            .with_tenant(fixtures::TENANT)
    }

    /// The rogue service principal.
    pub(crate) fn rogue() -> EntityRef {
        EntityRef::new(EntityKind::ServicePrincipal, fixtures::ROGUE_PRINCIPAL_ID)
            .with_name("Sync Helper")
            .with_tenant(fixtures::TENANT)
    }

    /// Makes one deterministic detection.
    pub(crate) fn detection(
        rule_id: &str,
        verdict: Verdict,
        technique: &str,
        entities: Vec<EntityRef>,
    ) -> Detection {
        Detection {
            id: DetectionId::new(),
            rule_id: rule_id.to_owned(),
            title: format!("Rule {rule_id}"),
            description: format!("The rule {rule_id} found activity."),
            severity: Severity::High,
            verdict,
            tier: DetectionTier::Deterministic,
            time: fixtures::base_time(),
            attack: vec![AttackTechnique::new("tactic", technique, "Technique")],
            event_ids: Vec::new(),
            entities,
            tenant: Some(fixtures::TENANT.to_owned()),
            attributes: BTreeMap::new(),
        }
    }

    /// Makes an incident like the one that the recorded attack log gives.
    pub(crate) fn attack_incident() -> Incident {
        let detections = vec![
            detection(
                "velocity.sign_in_burst",
                Verdict::Malicious,
                fixtures::expected::PASSWORD_SPRAY,
                vec![spray_ip(), victim()],
            ),
            detection(
                "velocity.credential_after_grant",
                Verdict::Malicious,
                fixtures::expected::CREDENTIAL_ADD,
                vec![rogue(), victim()],
            ),
            detection(
                "velocity.self_role_assignment",
                Verdict::Malicious,
                fixtures::expected::ROLE_ASSIGN,
                vec![rogue()],
            ),
        ];
        Incident {
            id: IncidentId::new(),
            title: "Password spray and rogue service principal".to_owned(),
            summary: String::new(),
            severity: Severity::Critical,
            status: IncidentStatus::Open,
            created_at: fixtures::base_time(),
            updated_at: fixtures::base_time(),
            tenant: Some(fixtures::TENANT.to_owned()),
            attack: detections
                .iter()
                .flat_map(|detection| detection.attack.clone())
                .collect(),
            entities: vec![spray_ip(), victim(), rogue()],
            detections,
            timeline: Vec::new(),
        }
    }

    /// Makes an incident with one detection that is only suspicious.
    pub(crate) fn suspicious_incident() -> Incident {
        let mut incident = attack_incident();
        incident.title = "Unusual sign-in".to_owned();
        incident.severity = Severity::Medium;
        incident.detections = vec![detection(
            "anomaly.new_country",
            Verdict::Suspicious,
            "T1078",
            vec![victim()],
        )];
        incident.entities = vec![victim()];
        incident
    }

    /// Makes a task with an incident for `role`.
    pub(crate) fn incident_task(role: AgentRole, incident: &Incident) -> AgentTask {
        AgentTask::new(role, AgentInput::Incident(Box::new(incident.clone())))
            .for_incident(incident.id)
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::common::{EntityKind, Severity};
    use aegis_contracts::incident::IncidentStore;
    use aegis_testkit::{Harness, ScriptedModel};

    use super::testing::*;
    use super::*;

    #[test]
    fn merge_keeps_the_agent_fields_and_adds_the_new_data() {
        let mut stored = suspicious_incident();
        stored.status = IncidentStatus::Contained;
        stored.summary = "The analyst wrote this.".to_owned();
        add_timeline(&mut stored, &AgentRole::Analyst, "Triage.", Vec::new());

        let mut incoming = stored.clone();
        incoming.status = IncidentStatus::Open;
        incoming.summary = "The correlator wrote this.".to_owned();
        incoming.timeline.clear();
        incoming.severity = Severity::Critical;
        incoming.detections.push(detection(
            "velocity.sign_in_burst",
            Verdict::Malicious,
            "T1110.003",
            vec![spray_ip()],
        ));
        incoming.entities.push(spray_ip());

        let (merged, delta) = merge(stored.clone(), &incoming);
        assert_eq!(
            delta,
            MergeDelta {
                is_new: false,
                new_detections: 1,
                changed: true
            }
        );
        assert_eq!(merged.status, IncidentStatus::Contained);
        assert_eq!(merged.summary, "The analyst wrote this.");
        assert_eq!(merged.severity, Severity::Critical);
        assert_eq!(merged.detections.len(), 2);
        assert_eq!(merged.entities, [victim(), spray_ip()]);
        assert_eq!(merged.timeline, stored.timeline);

        let (again, delta) = merge(merged.clone(), &incoming);
        assert_eq!(delta, MergeDelta::default());
        assert_eq!(again, merged);
    }

    #[tokio::test]
    async fn current_uses_the_store_and_reports_a_new_incident() {
        let harness = Harness::new(ScriptedModel::new("fake"));
        let context = harness.context("goal");
        let incident = attack_incident();
        let (found, delta) = current(&context, &incident).await.unwrap();
        assert_eq!(found, incident);
        assert!(delta.is_new);
        assert_eq!(delta.new_detections, 3);

        let mut stored = incident.clone();
        stored.status = IncidentStatus::Investigating;
        harness.incidents.save(&stored).await.unwrap();
        let (found, delta) = current(&context, &incident).await.unwrap();
        assert_eq!(found.status, IncidentStatus::Investigating);
        assert_eq!(delta, MergeDelta::default());

        let missing = by_id(&context, IncidentId::new()).await.unwrap_err();
        assert!(matches!(missing, Error::NotFound(_)));
        assert_eq!(by_id(&context, incident.id).await.unwrap(), stored);
    }

    #[test]
    fn evidence_links_the_incident_and_each_detection() {
        let incident = attack_incident();
        let links = evidence(&incident);
        assert_eq!(links.len(), 4);
        assert_eq!(
            links[0],
            EvidenceRef::new(EvidenceKind::Incident, incident.id)
        );
        assert_eq!(links[1].kind, EvidenceKind::Detection);
        assert_eq!(links[1].id, incident.detections[0].id.to_string());
        assert_eq!(links[1].note.as_deref(), Some("velocity.sign_in_burst"));
    }

    #[test]
    fn the_timeline_stays_in_time_order_and_names_the_author() {
        let mut incident = attack_incident();
        add_timeline(&mut incident, &AgentRole::Monitor, "First.", Vec::new());
        add_timeline(&mut incident, &AgentRole::Analyst, "Second.", Vec::new());
        assert_eq!(incident.timeline.len(), 2);
        assert!(incident.timeline.is_sorted_by_key(|entry| entry.time));
        assert_eq!(incident.timeline[1].author, "analyst");
        assert!(incident.updated_at > fixtures_base());
        assert_eq!(
            last_entry_by(&incident, &AgentRole::Monitor)
                .unwrap()
                .description,
            "First."
        );
        assert!(last_entry_by(&incident, &AgentRole::Responder).is_none());
    }

    fn fixtures_base() -> chrono::DateTime<Utc> {
        aegis_testkit::fixtures::base_time()
    }

    #[test]
    fn the_deterministic_signals_read_the_verdicts_and_the_honeytoken_records() {
        let attack = attack_incident();
        assert!(has_malicious_detection(&attack));
        assert!(!has_honeytoken_trip(&attack));

        let mut suspicious = suspicious_incident();
        assert!(!has_malicious_detection(&suspicious));
        suspicious.detections[0]
            .attributes
            .insert(attr::HONEYTOKEN_ID.to_owned(), json!("honeytoken-1"));
        assert!(has_honeytoken_trip(&suspicious));

        let mut escalated = suspicious_incident();
        add_timeline(
            &mut escalated,
            &AgentRole::Deception,
            "Trip.",
            vec![EvidenceRef::new(EvidenceKind::Event, "e-1").with_note(HONEYTOKEN_TRIP_NOTE)],
        );
        assert!(has_honeytoken_trip(&escalated));

        let mut forged = suspicious_incident();
        add_timeline(
            &mut forged,
            &AgentRole::Analyst,
            "Not from the deception agent.",
            vec![EvidenceRef::new(EvidenceKind::Event, "e-1").with_note(HONEYTOKEN_TRIP_NOTE)],
        );
        assert!(!has_honeytoken_trip(&forged));
    }

    #[test]
    fn involved_entities_have_no_duplicates_and_no_benign_detections() {
        let mut incident = attack_incident();
        incident.detections.push(detection(
            "noise",
            Verdict::Benign,
            "T0000",
            vec![EntityRef::new(EntityKind::Host, "host-benign")],
        ));
        incident.detections.push(detection(
            "extra",
            Verdict::Suspicious,
            "T0001",
            vec![EntityRef::new(EntityKind::Host, "host-1")],
        ));
        let entities = involved_entities(&incident);
        assert_eq!(
            entities,
            [
                spray_ip(),
                victim(),
                rogue(),
                EntityRef::new(EntityKind::Host, "host-1")
            ]
        );
    }

    #[test]
    fn the_view_has_the_facts_and_no_event_identifiers() {
        let mut incident = attack_incident();
        incident.detections[0].event_ids = vec![aegis_contracts::EventId::new(); 600];
        let view = incident_view(&incident);
        assert_eq!(view["severity"], "critical");
        assert_eq!(view["detection_count"], 3);
        assert_eq!(view["detections"][0]["event_count"], 600);
        assert!(view["detections"][0].get("event_ids").is_none());
        assert_eq!(
            view["entities"][2]["node"],
            "service_principal:sp-sync-helper"
        );
        assert_eq!(view["detections"][0]["techniques"], json!(["T1110.003"]));
    }

    #[test]
    fn tokens_and_labels_use_the_serde_names() {
        assert_eq!(token(&EntityKind::ServicePrincipal), "service_principal");
        assert_eq!(token(&IncidentStatus::FalsePositive), "false_positive");
        assert_eq!(entity_label(&rogue()), "service_principal sp-sync-helper");
        assert_eq!(one_line("a\n  b\tc\u{7}"), "a b c");
    }
}
