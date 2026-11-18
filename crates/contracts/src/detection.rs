//! The contract for detectors and the detection type.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{DetectionId, EntityRef, EventId, Severity};
use crate::error::Result;
use crate::event::Event;

/// The detection tier that made a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTier {
    /// Tier 1. A rule, an indicator match, or a velocity detector. No LLM.
    Deterministic,
    /// Tier 2. LLM analysis.
    Llm,
}

/// The conclusion of a detector about the activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The activity is an attack. No more analysis is necessary before a response.
    Malicious,
    /// The activity is possibly an attack. Tier 2 must analyze it.
    Suspicious,
    /// The activity is not an attack.
    Benign,
}

/// A MITRE ATT&CK technique.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttackTechnique {
    /// The tactic, in lower case with `-` between words, for example `privilege-escalation`.
    pub tactic: String,
    /// The technique identifier, for example `T1098.001`.
    pub technique_id: String,
    /// The name of the technique.
    pub name: String,
}

impl AttackTechnique {
    /// Makes a technique.
    pub fn new(
        tactic: impl Into<String>,
        technique_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            tactic: tactic.into(),
            technique_id: technique_id.into(),
            name: name.into(),
        }
    }
}

/// One finding of a detector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// The identifier of the detection.
    pub id: DetectionId,
    /// The identifier of the rule or the detector that made the detection.
    pub rule_id: String,
    /// A short title.
    pub title: String,
    /// An explanation of what the detector found.
    pub description: String,
    /// The severity of the detection.
    pub severity: Severity,
    /// The conclusion of the detector.
    pub verdict: Verdict,
    /// The tier that made the detection.
    pub tier: DetectionTier,
    /// The time of the last event that caused the detection.
    pub time: DateTime<Utc>,
    /// The ATT&CK techniques that the detection maps to.
    #[serde(default)]
    pub attack: Vec<AttackTechnique>,
    /// The events that caused the detection.
    #[serde(default)]
    pub event_ids: Vec<EventId>,
    /// The entities that the detection involves.
    #[serde(default)]
    pub entities: Vec<EntityRef>,
    /// The tenant in which the activity occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// More data from the detector, for example a count or a rate.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// A detector. It examines each event and returns zero or more detections.
///
/// A detector can keep state between events, for example a count in a time window. An
/// implementation must be safe to share between tasks.
#[async_trait]
pub trait Detector: Send + Sync {
    /// Returns the identifier of this detector.
    fn id(&self) -> &str;

    /// Returns the tier of this detector.
    fn tier(&self) -> DetectionTier;

    /// Examines one event.
    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>>;
}
