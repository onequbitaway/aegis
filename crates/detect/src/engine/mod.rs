//! The detection engine: tier 1, tier 2, and the correlator as one unit.
//!
//! [`DetectionEngine::process`] examines one event:
//!
//! 1. Tier 1 runs: the Sigma rules and the indicators of the active rule pack, then the
//!    velocity detectors. Tier 1 uses no model.
//! 2. Tier 2 runs only for a tier 1 detection that is `suspicious`, and only if the engine
//!    has a model. A `malicious` detection and an event with no detection never reach the
//!    model.
//! 3. The correlator folds the detections into incidents.
//!
//! [`DetectionEngine::run`] connects the engine to the message bus.
//!
//! # Flood protection
//!
//! An attacker can send events only to make the engine work. The engine has three limits.
//! Refer to the [`flood`](crate::flood) module.
//!
//! - A rule with `aegis.suppress`, and an indicator with `suppress_seconds`, give one
//!   detection for one key in a window. [`DetectionEngine::suppression_summaries`] returns
//!   the counts of the other matches.
//! - Tier 2 has a quota of model requests for each source connector and each tenant. A
//!   detection over the quota stays `suspicious` and records `quota`.
//! - The bus runner publishes a limited number of states of one incident in a window.
//!
//! [`DetectionEngine::flood_counters`] returns the count of each limit.
//!
//! # Rule packs
//!
//! [`DetectionEngine::reload`] replaces the active rule pack while the engine runs. Each
//! event uses one pack from start to end. No event waits for a reload, and no event is
//! lost. The state of the velocity detectors and the incidents stay.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use aegis_contracts::common::IncidentId;
use aegis_contracts::event::{Event, attr};
use aegis_contracts::model::ModelProvider;
use aegis_contracts::{Detection, DetectionTier, Detector, Incident, Result, Verdict};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::common::{clean_text, event_tenant, fingerprint_token, kind_name, lock};
use crate::correlate::{Correlator, CorrelatorConfig};
use crate::error::DetectError;
use crate::export::USER_AGENT_ATTRIBUTE;
use crate::flood::{
    Admission, FloodCounters, FloodMeter, SuppressionSummary, Suppressor, TriageQuota, entity_key,
};
use crate::llm::{LlmTriage, LlmTriageConfig, with_triage_failure, with_triage_quota};
use crate::pack::RulePack;
use crate::sigma::SigmaRule;
use crate::velocity::{
    CredentialAfterGrant, EndpointProbe, ImpossibleSpeed, MachineCadence, PrivilegedSelfAssignment,
    SignInBurst, VelocityConfig,
};

mod runner;

pub use runner::{BusRunnerConfig, DEFAULT_DURABLE_NAME, RunSummary};

/// The key of the detection attribute that holds the number of matches that a rule
/// counted for the same key in the window before the detection.
pub const PREVIOUS_MATCHES_ATTRIBUTE: &str = "previous_window_matches";

/// The number of characters of a user agent that a detection of a decoy keeps.
const MAX_USER_AGENT_CHARS: usize = 256;

/// The settings of the [`DetectionEngine`].
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    /// The settings of the velocity detectors.
    pub velocity: VelocityConfig,
    /// The settings of the correlator.
    pub correlator: CorrelatorConfig,
    /// The settings of tier 2. The engine uses them only after
    /// [`DetectionEngine::with_triage`].
    pub triage: LlmTriageConfig,
}

/// What the engine found for one event.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EngineOutput {
    /// The new detections, tier 1 first in detector order. The result of tier 2 for a
    /// detection comes immediately after that detection.
    pub detections: Vec<Detection>,
    /// The incidents that are new or that changed, each in its last state. An incident
    /// that a merge replaced comes before the incident that replaces it.
    pub incidents: Vec<Incident>,
}

impl EngineOutput {
    /// Returns `true` if the event gave no detection and changed no incident.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detections.is_empty() && self.incidents.is_empty()
    }
}

/// The two-tier detection engine with its correlator.
///
/// One engine holds the state of the velocity detectors and the open incidents. Send it
/// the events of one stream in the order of the stream. The engine is safe to share
/// between tasks, but events that tasks send at the same time have no defined order.
pub struct DetectionEngine {
    pack: RwLock<Arc<RulePack>>,
    burst: SignInBurst,
    self_assignment: PrivilegedSelfAssignment,
    credential: CredentialAfterGrant,
    speed: ImpossibleSpeed,
    cadence: MachineCadence,
    probe: EndpointProbe,
    added: Vec<Arc<dyn Detector>>,
    triage_config: LlmTriageConfig,
    triage: Option<LlmTriage>,
    quota: Mutex<TriageQuota>,
    suppressor: Mutex<Suppressor>,
    meter: FloodMeter,
    correlator: Mutex<Correlator>,
}

impl DetectionEngine {
    /// Makes an engine with a rule pack and no model. Tier 2 does not run.
    ///
    /// Use [`RulePack::empty`] for an engine that runs only the velocity detectors.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if a setting is not valid.
    pub fn new(config: EngineConfig, pack: RulePack) -> std::result::Result<Self, DetectError> {
        config.triage.validate()?;
        let quota = TriageQuota::new(
            config.triage.quota_window()?,
            config.triage.max_requests_per_source,
            config.triage.max_requests_per_tenant,
        );
        Ok(Self {
            pack: RwLock::new(Arc::new(pack)),
            burst: SignInBurst::new(config.velocity.sign_in_burst)?,
            self_assignment: PrivilegedSelfAssignment::new(
                config.velocity.privileged_self_assignment,
            ),
            credential: CredentialAfterGrant::new(config.velocity.credential_after_grant)?,
            speed: ImpossibleSpeed::new(config.velocity.impossible_speed)?,
            cadence: MachineCadence::new(config.velocity.machine_cadence)?,
            probe: EndpointProbe::new(config.velocity.endpoint_probe)?,
            added: Vec::new(),
            triage_config: config.triage,
            triage: None,
            quota: Mutex::new(quota),
            suppressor: Mutex::new(Suppressor::new()),
            meter: FloodMeter::default(),
            correlator: Mutex::new(Correlator::new(config.correlator)?),
        })
    }

    /// Sets the model for tier 2. `model` is a provider or the model router.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if the tier 2 settings are not valid.
    pub fn with_triage(
        mut self,
        model: Arc<dyn ModelProvider>,
    ) -> std::result::Result<Self, DetectError> {
        self.triage = Some(LlmTriage::new(model, self.triage_config.clone())?);
        Ok(self)
    }

    /// Adds a detector to the engine, for example a detector from a plugin.
    ///
    /// The engine calls the added detectors before its own detectors. If an added detector
    /// returns an error, [`DetectionEngine::process`] returns that error and the event does
    /// not change the state of the engine.
    #[must_use]
    pub fn with_detector(mut self, detector: Arc<dyn Detector>) -> Self {
        self.added.push(detector);
        self
    }

    /// Returns the active rule pack.
    #[must_use]
    pub fn pack(&self) -> Arc<RulePack> {
        self.pack
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Makes `pack` the active rule pack. Returns the pack that was active before.
    ///
    /// The change is atomic. An event that the engine examines at the time of the call
    /// completes with the old pack. Each later event uses the new pack.
    pub fn reload(&self, pack: RulePack) -> Arc<RulePack> {
        let pack = Arc::new(pack);
        tracing::info!(
            pack = %pack.manifest().name,
            version = %pack.manifest().version,
            rules = pack.rules().len(),
            indicators = pack.indicators().len(),
            "the detection engine loaded a rule pack"
        );
        let mut active = self.pack.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *active, pack)
    }

    /// Loads the pack in `directory` and makes it the active rule pack. Returns the pack
    /// that was active before.
    ///
    /// The function reads files and blocks the thread. In an asynchronous task, call it
    /// with `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns the error of [`RulePack::load`] if the pack is not valid. The engine then
    /// keeps the pack that was active before the call.
    pub fn reload_from_dir(
        &self,
        directory: impl AsRef<Path>,
    ) -> std::result::Result<Arc<RulePack>, DetectError> {
        let directory = directory.as_ref();
        match RulePack::load(directory) {
            Ok(pack) => Ok(self.reload(pack)),
            Err(error) => {
                tracing::warn!(
                    directory = %directory.display(),
                    error = %error,
                    "the detection engine rejected a rule pack and keeps the active pack"
                );
                Err(error)
            }
        }
    }

    /// Returns the incidents that the correlator keeps, oldest first.
    #[must_use]
    pub fn incidents(&self) -> Vec<Incident> {
        lock(&self.correlator).incidents()
    }

    /// Removes an incident from the correlator. Returns `false` if it is not there.
    ///
    /// Call this when an incident is resolved or is a false positive. A later detection for
    /// the same entities then starts a new incident.
    pub fn forget_incident(&self, id: IncidentId) -> bool {
        lock(&self.correlator).forget(id)
    }

    /// Returns the counts of the flood protection, from the start of the engine.
    #[must_use]
    pub fn flood_counters(&self) -> FloodCounters {
        self.meter.read()
    }

    /// Returns the suppression windows that counted more than one match, in order of rule
    /// and time.
    ///
    /// Each summary names a rule or an indicator, a key, and the number of matches. The
    /// first match gave the detection of the summary. The other matches gave no detection.
    /// The engine keeps a limited number of windows and drops those that it used least
    /// recently.
    #[must_use]
    pub fn suppression_summaries(&self) -> Vec<SuppressionSummary> {
        lock(&self.suppressor).summaries()
    }

    /// Applies the suppression settings of one Sigma rule to one match of the rule.
    fn admit_rule(
        &self,
        event: &Event,
        rule: &SigmaRule,
        mut detection: Detection,
        found: &mut Vec<Detection>,
    ) {
        let Some(suppression) = rule.suppression() else {
            found.push(detection);
            return;
        };
        let key = suppression
            .key(event)
            .unwrap_or_else(|| entity_key(&detection));
        let window = i64::try_from(suppression.window_seconds())
            .ok()
            .and_then(TimeDelta::try_seconds)
            .unwrap_or(TimeDelta::MAX);
        let repeat = suppression.repeat();
        let admission = lock(&self.suppressor).admit(
            &detection,
            &key,
            window,
            repeat.map(|repeat| repeat.count),
        );
        match admission {
            Admission::Emit { previous_matches } => {
                if previous_matches > 0 {
                    detection.attributes.insert(
                        PREVIOUS_MATCHES_ATTRIBUTE.to_owned(),
                        json!(previous_matches),
                    );
                }
                found.push(detection);
            }
            Admission::Suppress => self.meter.suppressed(),
            Admission::Repeat {
                matches,
                first_event,
                first_detection,
            } => {
                self.meter.suppressed();
                if let Some(repeat) = repeat {
                    self.meter.repeated();
                    found.push(rule.repeat_detection(
                        event,
                        repeat,
                        matches,
                        (first_event, first_detection),
                    ));
                }
            }
        }
    }

    /// Applies the suppression time of one indicator to one match of the indicator.
    fn admit_indicator(
        &self,
        event: &Event,
        window: Option<TimeDelta>,
        mut detection: Detection,
        found: &mut Vec<Detection>,
    ) {
        let Some(window) = window else {
            found.push(detection);
            return;
        };
        let text = |key: &str| {
            detection
                .attributes
                .get(key)
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_owned()
        };
        let key = [
            text("matched_field"),
            text("matched_value"),
            kind_name(event.actor.kind).to_owned(),
            event.actor.id.clone(),
        ];
        match lock(&self.suppressor).admit(&detection, &key, window, None) {
            Admission::Emit { previous_matches } => {
                if previous_matches > 0 {
                    detection.attributes.insert(
                        PREVIOUS_MATCHES_ATTRIBUTE.to_owned(),
                        json!(previous_matches),
                    );
                }
                found.push(detection);
            }
            Admission::Suppress | Admission::Repeat { .. } => self.meter.suppressed(),
        }
    }

    /// Runs tier 1 on one event.
    fn tier_one(&self, event: &Event, added: Vec<Detection>) -> Vec<Detection> {
        let pack = self.pack();
        let mut found = Vec::new();
        for (rule, detection) in pack.sigma().matches(event) {
            self.admit_rule(event, rule, detection, &mut found);
        }
        for (window, detection) in pack.indicators().matches(event) {
            self.admit_indicator(event, window, detection, &mut found);
        }
        found.extend(self.burst.evaluate(event));
        found.extend(self.self_assignment.evaluate(event));
        found.extend(self.credential.evaluate(event));
        found.extend(self.speed.evaluate(event));
        found.extend(self.cadence.evaluate(event));
        found.extend(self.probe.evaluate(event));
        found.extend(added);
        mark_decoy_detections(event, &mut found);
        found
    }

    /// Examines one event. Returns the new detections and the incidents that are new or
    /// that changed.
    ///
    /// A `suspicious` tier 1 detection goes to tier 2 if the engine has a model. The
    /// output then holds the tier 1 detection and the tier 2 result, and the correlator
    /// gets only the tier 2 result. A `benign` result joins no incident.
    ///
    /// If the model fails, the tier 1 detection stays `suspicious`, records the failure in
    /// its `triage` attribute, and goes to the correlator. A model failure is not an error
    /// of this function.
    ///
    /// Tier 2 has a quota of model requests for each source connector and each tenant.
    /// If a quota has no request left, the engine sends no request. The tier 1 detection
    /// stays `suspicious`, records the status `quota` in its `triage` attribute, and goes
    /// to the correlator.
    ///
    /// A rule with `aegis.suppress` and an indicator with `suppress_seconds` give one
    /// detection for one key in a window. A later match in the window gives no detection.
    ///
    /// # Errors
    ///
    /// Returns the error of a detector that [`DetectionEngine::with_detector`] added. The
    /// detectors of the engine do not fail.
    pub async fn process(&self, event: &Event) -> Result<EngineOutput> {
        let mut added: Vec<Detection> = Vec::new();
        for detector in &self.added {
            added.extend(detector.inspect(event).await?);
        }
        let found = self.tier_one(event, added);
        if found.is_empty() {
            return Ok(EngineOutput::default());
        }

        let mut output = EngineOutput {
            detections: Vec::with_capacity(found.len()),
            incidents: Vec::new(),
        };
        // The positions in `output.detections` of the detections for the correlator.
        let mut for_correlator: Vec<usize> = Vec::with_capacity(found.len());
        for detection in found {
            let is_for_tier_two = detection.verdict == Verdict::Suspicious
                && detection.tier == DetectionTier::Deterministic;
            let Some(triage) = self.triage.as_ref().filter(|_| is_for_tier_two) else {
                for_correlator.push(output.detections.len());
                output.detections.push(detection);
                continue;
            };
            let taken = lock(&self.quota).take(
                &event.source.connector,
                detection.tenant.as_deref().or(event_tenant(event)),
                event.time,
            );
            if let Err(scope) = taken {
                // No request goes to the model. The detection stays in the pipeline.
                self.meter.quota_denied();
                let limit = lock(&self.quota).limit(scope);
                for_correlator.push(output.detections.len());
                output.detections.push(with_triage_quota(
                    &detection,
                    scope.name(),
                    limit,
                    self.triage_config.quota_window_seconds,
                ));
                continue;
            }
            match triage.triage(&detection, std::slice::from_ref(event)).await {
                Ok(result) => {
                    output.detections.push(detection);
                    for_correlator.push(output.detections.len());
                    output.detections.push(result);
                }
                Err(error) => {
                    tracing::warn!(
                        rule_id = %detection.rule_id,
                        detection_id = %detection.id,
                        error = %error,
                        "tier 2 failed; the detection stays suspicious"
                    );
                    for_correlator.push(output.detections.len());
                    output
                        .detections
                        .push(with_triage_failure(&detection, &error));
                }
            }
        }

        let mut correlator = lock(&self.correlator);
        for detection in for_correlator
            .into_iter()
            .filter_map(|position| output.detections.get(position))
        {
            for incident in correlator.add(detection) {
                output.incidents.retain(|known| known.id != incident.id);
                output.incidents.push(incident);
            }
        }
        drop(correlator);
        Ok(output)
    }
}

/// Adds the data of the client to each detection of an event that comes from a decoy.
///
/// An event from a decoy has the attribute `decoy_id`. Its detections get the attributes
/// `decoy_id`, `decoy_kind`, `client_fingerprint`, and `user_agent`, so that the
/// [`export`](crate::export) module can make indicators from them. The function does not
/// replace an attribute that a detector set.
fn mark_decoy_detections(event: &Event, detections: &mut [Detection]) {
    let Some(decoy_id) = event.attribute_str(attr::DECOY_ID) else {
        return;
    };
    let mut marks = vec![(attr::DECOY_ID, json!(clean_text(decoy_id, 128)))];
    if let Some(kind) = event.attribute_str(attr::DECOY_KIND) {
        marks.push((attr::DECOY_KIND, json!(clean_text(kind, 64))));
    }
    if let Some(token) = event
        .attribute_str(attr::CLIENT_FINGERPRINT)
        .and_then(fingerprint_token)
    {
        marks.push((attr::CLIENT_FINGERPRINT, json!(token)));
    }
    if let Some(user_agent) = event.actor.user_agent.as_deref() {
        marks.push((
            USER_AGENT_ATTRIBUTE,
            json!(clean_text(user_agent, MAX_USER_AGENT_CHARS)),
        ));
    }
    for detection in detections
        .iter_mut()
        .filter(|detection| detection.event_ids.contains(&event.id))
    {
        for (key, value) in &marks {
            detection
                .attributes
                .entry((*key).to_owned())
                .or_insert_with(|| value.clone());
        }
    }
}

#[cfg(test)]
mod tests;
