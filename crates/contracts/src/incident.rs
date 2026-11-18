//! The incident type and its store.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{EntityRef, EvidenceRef, IncidentId, Severity};
use crate::detection::{AttackTechnique, Detection};
use crate::error::Result;

/// The state of an incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// The incident is new. No agent has analyzed it.
    #[default]
    Open,
    /// An agent analyzes the incident.
    Investigating,
    /// Containment actions stopped the activity.
    Contained,
    /// The incident is complete.
    Resolved,
    /// Analysis found that the activity was not an attack.
    FalsePositive,
}

/// One entry in the timeline of an incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// The time of the entry.
    pub time: DateTime<Utc>,
    /// The component or the person that made the entry, for example `analyst`.
    pub author: String,
    /// What occurred.
    pub description: String,
    /// The evidence for the entry.
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

/// A set of related detections that describe one attack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    /// The identifier of the incident.
    pub id: IncidentId,
    /// A short title.
    pub title: String,
    /// An explanation of the incident.
    pub summary: String,
    /// The severity of the incident. This is at least the largest detection severity.
    pub severity: Severity,
    /// The state of the incident.
    #[serde(default)]
    pub status: IncidentStatus,
    /// The time at which the correlator made the incident.
    pub created_at: DateTime<Utc>,
    /// The time of the last change.
    pub updated_at: DateTime<Utc>,
    /// The tenant in which the activity occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The detections that the correlator put in this incident.
    #[serde(default)]
    pub detections: Vec<Detection>,
    /// The entities that the incident involves.
    #[serde(default)]
    pub entities: Vec<EntityRef>,
    /// The ATT&CK techniques of all detections, with no duplicates.
    #[serde(default)]
    pub attack: Vec<AttackTechnique>,
    /// The timeline of the incident, in time order.
    #[serde(default)]
    pub timeline: Vec<TimelineEntry>,
}

/// A store for incidents.
#[async_trait]
pub trait IncidentStore: Send + Sync {
    /// Writes an incident. An incident with the same identifier is replaced.
    async fn save(&self, incident: &Incident) -> Result<()>;

    /// Reads one incident.
    async fn get(&self, id: IncidentId) -> Result<Option<Incident>>;

    /// Lists incidents, newest first. With a status, lists only incidents in that state.
    async fn list(&self, status: Option<IncidentStatus>, limit: usize) -> Result<Vec<Incident>>;
}
