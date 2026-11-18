//! The machine-cadence detector.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;

use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{Event, Outcome, action, attr};
use aegis_contracts::{Detection, DetectionTier, Detector, Result, Verdict};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{Finding, Tracked, at_least, seconds, tenant_key};
use crate::attack::technique_in;
use crate::common::{
    canonical_ip, clean_text, ip_entity, lock, push_entity, time_after, time_before,
};
use crate::error::DetectError;

/// The rule identifier of a machine-cadence detection.
pub const MACHINE_CADENCE_RULE_ID: &str = "aegis.velocity.machine_cadence";

/// The smallest number of actions in a chain for the regularity test.
///
/// Fewer gaps do not show regularity: three gaps of a person are sometimes almost equal.
pub const REGULARITY_MIN_ACTIONS: usize = 6;

/// The largest number of different actions that the detector keeps for one principal or
/// one address.
pub const MAX_CHAIN_ACTIONS: usize = 16;

/// The number of characters of an action name or an operation name that a detection keeps.
const MAX_LABEL_CHARS: usize = 64;

/// The settings of [`MachineCadence`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MachineCadenceConfig {
    /// Set to `false` to stop the detector.
    pub enabled: bool,
    /// The length in seconds of the window that holds one chain.
    pub window_seconds: u64,
    /// The smallest number of different actions that is a chain.
    pub min_actions: usize,
    /// The largest median gap in milliseconds that is too short for a person.
    pub max_median_gap_milliseconds: u64,
    /// The largest coefficient of variation of the gaps that is too regular for a person.
    /// The coefficient is the standard deviation of the gaps divided by their mean.
    pub max_coefficient_of_variation: f64,
    /// The sensitive actions. A chain must have one or more of them.
    pub sensitive_actions: Vec<String>,
    /// The actions that are a step of a chain, but that do not make a chain sensitive.
    pub supporting_actions: Vec<String>,
    /// With `true`, the detector also follows each address across principals. Set to
    /// `false` if many principals share one address, for example behind a proxy.
    pub follow_addresses: bool,
    /// The identifiers of the principals that the detector ignores. Use this for an
    /// approved automation that makes changes at machine speed, for example a
    /// provisioning service.
    pub ignored_principals: Vec<String>,
    /// The time in seconds after a detection in which the detector reports no more chains
    /// for the same principal or address.
    pub cooldown_seconds: u64,
    /// The largest number of principals and addresses for which the detector keeps state.
    pub max_tracked_keys: usize,
}

impl Default for MachineCadenceConfig {
    fn default() -> Self {
        let names = |actions: &[&str]| actions.iter().map(|name| (*name).to_owned()).collect();
        Self {
            enabled: true,
            window_seconds: 300,
            min_actions: 4,
            max_median_gap_milliseconds: 5_000,
            max_coefficient_of_variation: 0.1,
            sensitive_actions: names(&[
                action::OAUTH_CONSENT_GRANT,
                action::APP_CREATE,
                action::APP_CREDENTIAL_ADD,
                action::APP_CREDENTIAL_REMOVE,
                action::APP_PERMISSION_GRANT,
                action::SERVICE_PRINCIPAL_CREATE,
                action::SERVICE_PRINCIPAL_DISABLE,
                action::ROLE_ASSIGN,
                action::ROLE_REMOVE,
                action::USER_CREATE,
                action::USER_UPDATE,
                action::USER_PASSWORD_RESET,
                action::MFA_METHOD_CHANGE,
                action::SECRET_READ,
                action::HONEYTOKEN_TRIP,
            ]),
            supporting_actions: names(&[action::SIGN_IN, action::API_CALL]),
            follow_addresses: true,
            ignored_principals: Vec::new(),
            cooldown_seconds: 900,
            max_tracked_keys: 100_000,
        }
    }
}

/// The owner of a chain.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Subject {
    Principal(EntityKind, String),
    Address(IpAddr),
}

/// The first event of one action in the window.
#[derive(Clone)]
struct Step {
    /// A number that identifies the action.
    signature: u64,
    time: DateTime<Utc>,
    event_id: EventId,
    /// The name of the action, for the detection.
    label: String,
    sensitive: bool,
    /// `true` for a sensitive action with the attribute `privileged: true`.
    privileged: bool,
    /// A number that identifies the actor.
    actor: u64,
    ip: Option<IpAddr>,
}

impl Step {
    fn of(event: &Event, sensitive: bool) -> Self {
        let operation = (event.action == action::API_CALL)
            .then(|| event.attribute_str(attr::OPERATION))
            .flatten();
        let mut signature = DefaultHasher::new();
        event.action.hash(&mut signature);
        operation.hash(&mut signature);
        let mut actor = DefaultHasher::new();
        event.actor.kind.hash(&mut actor);
        event.actor.id.hash(&mut actor);
        let mut label = clean_text(&event.action, MAX_LABEL_CHARS);
        if let Some(operation) = operation {
            label.push(' ');
            label.push_str(&clean_text(operation, MAX_LABEL_CHARS));
        }
        Self {
            signature: signature.finish(),
            time: event.time,
            event_id: event.id,
            label,
            sensitive,
            privileged: sensitive && event.attribute_bool(attr::PRIVILEGED) == Some(true),
            actor: actor.finish(),
            ip: event.actor.ip.map(canonical_ip),
        }
    }
}

#[derive(Default)]
struct Chain {
    /// The steps in the window, in time order. Each action is there one time.
    steps: Vec<Step>,
    /// The end of the cooldown, and `true` if the detection was `malicious`.
    alert: Option<(DateTime<Utc>, bool)>,
}

/// Why a chain is not the work of a person.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cadence {
    /// The median gap is too short.
    Short,
    /// The gaps are too regular.
    Regular,
}

/// A chain that the detector reports.
struct Report {
    steps: Vec<Step>,
    cadence: Cadence,
    median_milliseconds: i64,
    coefficient_of_variation: Option<f64>,
    by_address: bool,
    malicious: bool,
}

/// The gaps between the steps of a run. A run is in time order, so no gap is negative.
fn gaps(run: &[Step]) -> Vec<TimeDelta> {
    run.iter()
        .zip(run.iter().skip(1))
        .map(|(earlier, later)| (later.time - earlier.time).max(TimeDelta::zero()))
        .collect()
}

/// Returns the median of the gaps in milliseconds, or `None` for no gap.
fn median(gaps: &[TimeDelta]) -> Option<i64> {
    let mut sorted: Vec<i64> = gaps.iter().map(|gap| gap.num_milliseconds()).collect();
    sorted.sort_unstable();
    let middle = sorted.len() / 2;
    let upper = *sorted.get(middle)?;
    if sorted.len() % 2 == 1 {
        return Some(upper);
    }
    let lower = *sorted.get(middle.checked_sub(1)?)?;
    Some(lower.saturating_add(upper) / 2)
}

/// Returns the standard deviation of the gaps divided by their mean.
///
/// Returns `None` for fewer than two gaps, and for gaps with a mean of zero.
fn coefficient_of_variation(gaps: &[TimeDelta]) -> Option<f64> {
    if gaps.len() < 2 {
        return None;
    }
    let count = f64::from(u32::try_from(gaps.len()).ok()?);
    let values = || gaps.iter().map(|gap| gap.as_seconds_f64());
    let mean = values().sum::<f64>() / count;
    if mean <= 0.0 {
        return None;
    }
    let variance = values().map(|gap| (gap - mean).powi(2)).sum::<f64>() / count;
    Some(variance.sqrt() / mean)
}

/// Finds one principal or one address that does a chain of different sensitive actions at
/// the speed or the regularity of a machine.
///
/// A **step** is an event that did not fail and whose action is in `sensitive_actions` or
/// in `supporting_actions`. Two `api.call` events with different `operation` attributes
/// are different actions. The detector keeps the first event of each action in the window.
/// A job that does one action again and again thus never makes a chain.
///
/// The detector reports a chain when the newest `min_actions` steps have one or more
/// sensitive actions and one of these is true:
///
/// - The median gap is at most `max_median_gap_milliseconds`: the gaps are too short.
/// - The newest [`REGULARITY_MIN_ACTIONS`] steps (or `min_actions`, if that is larger)
///   have a coefficient of variation of at most `max_coefficient_of_variation`: the gaps
///   are too regular.
///
/// The detection is `suspicious`. It is `malicious` when the chain of a principal includes
/// a privileged change: a sensitive action with the attribute `privileged: true`.
///
/// The detector follows each user, service principal, and application. With
/// `follow_addresses`, it also follows each address, and reports a chain that two or more
/// principals made from one address. An actor that is not a principal has only the chain
/// of its address. A chain of an address is always `suspicious`, because principals can
/// share an address.
///
/// After a detection, the detector reports the same principal or address again only after
/// the cooldown, or when a `malicious` chain follows a `suspicious` detection.
///
/// # Technique
///
/// The technique is `T1059.009` (Command and Scripting Interpreter: Cloud API). ATT&CK has
/// no technique for automated activity as such. A chain of control-plane actions at
/// machine speed shows a script or an agent that uses the cloud API, which is this
/// technique.
pub struct MachineCadence {
    config: MachineCadenceConfig,
    window: TimeDelta,
    cooldown: TimeDelta,
    state: Mutex<Tracked<(u64, Subject), Chain>>,
}

impl MachineCadence {
    /// Makes the detector.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if the window is zero, `min_actions` is less than 2
    /// or more than [`MAX_CHAIN_ACTIONS`], `max_coefficient_of_variation` is not a number
    /// of 0 or more, `sensitive_actions` is empty, an action name is empty, or
    /// `max_tracked_keys` is zero.
    pub fn new(config: MachineCadenceConfig) -> std::result::Result<Self, DetectError> {
        let prefix = "machine_cadence";
        at_least(
            &format!("{prefix}.window_seconds"),
            usize::try_from(config.window_seconds).unwrap_or(usize::MAX),
            1,
        )?;
        at_least(&format!("{prefix}.min_actions"), config.min_actions, 2)?;
        if config.min_actions > MAX_CHAIN_ACTIONS {
            return Err(DetectError::Config(format!(
                "{prefix}.min_actions must be {MAX_CHAIN_ACTIONS} or less, but it is {}",
                config.min_actions
            )));
        }
        let variation = config.max_coefficient_of_variation;
        if !(variation.is_finite() && variation >= 0.0) {
            return Err(DetectError::Config(format!(
                "{prefix}.max_coefficient_of_variation must be a number of 0 or more, but it \
                 is {variation}"
            )));
        }
        if config.sensitive_actions.is_empty() {
            return Err(DetectError::Config(format!(
                "{prefix}.sensitive_actions is empty; set enabled = false to stop the detector"
            )));
        }
        let names = config
            .sensitive_actions
            .iter()
            .chain(&config.supporting_actions);
        if names.into_iter().any(|name| name.trim().is_empty()) {
            return Err(DetectError::Config(format!(
                "{prefix}: an action name is empty"
            )));
        }
        at_least(
            &format!("{prefix}.max_tracked_keys"),
            config.max_tracked_keys,
            1,
        )?;
        Ok(Self {
            window: seconds(&format!("{prefix}.window_seconds"), config.window_seconds)?,
            cooldown: seconds(
                &format!("{prefix}.cooldown_seconds"),
                config.cooldown_seconds,
            )?,
            state: Mutex::new(Tracked::new(config.max_tracked_keys)),
            config,
        })
    }

    /// Examines one event. Returns a detection if the event completes a chain.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Option<Detection> {
        if !self.config.enabled || event.outcome == Outcome::Failure {
            return None;
        }
        let listed = |actions: &[String]| actions.iter().any(|name| name.as_str() == event.action);
        let sensitive = listed(&self.config.sensitive_actions);
        if !sensitive && !listed(&self.config.supporting_actions) {
            return None;
        }
        if self.config.ignored_principals.contains(&event.actor.id) {
            return None;
        }
        let is_principal = matches!(
            event.actor.kind,
            EntityKind::User | EntityKind::ServicePrincipal | EntityKind::Application
        );
        let step = Step::of(event, sensitive);
        let tenant = tenant_key(event);

        let mut tracked = lock(&self.state);
        let mut report = None;
        if is_principal {
            let key = (
                tenant,
                Subject::Principal(event.actor.kind, event.actor.id.clone()),
            );
            report = self.advance(&mut tracked, key, &step, false, true);
        }
        if let Some(ip) = step
            .ip
            .filter(|_| self.config.follow_addresses || !is_principal)
        {
            let key = (tenant, Subject::Address(ip));
            if report.is_some() {
                // The chain of the principal has these steps. The address starts again.
                if let Some(chain) = tracked.get_mut(&key) {
                    chain.steps.clear();
                }
            } else {
                report = self.advance(&mut tracked, key, &step, true, is_principal);
            }
        }
        drop(tracked);
        report.map(|report| self.detection(event, &report))
    }

    /// Adds a step to the chain of one subject. Returns the chain, if it is complete.
    fn advance(
        &self,
        tracked: &mut Tracked<(u64, Subject), Chain>,
        key: (u64, Subject),
        step: &Step,
        by_address: bool,
        actor_is_principal: bool,
    ) -> Option<Report> {
        let chain = tracked.upsert(key, step.time, Chain::default);
        let mut only_malicious = false;
        if let Some((until, was_malicious)) = chain.alert {
            if step.time >= until {
                chain.alert = None;
            } else if was_malicious {
                return None;
            } else {
                only_malicious = true;
            }
        }

        let newest = chain
            .steps
            .last()
            .map_or(step.time, |last| last.time.max(step.time));
        let horizon = time_before(newest, self.window);
        chain.steps.retain(|known| known.time > horizon);
        if step.time <= horizon
            || chain
                .steps
                .iter()
                .any(|known| known.signature == step.signature)
        {
            return None;
        }
        let mut position = chain.steps.partition_point(|known| known.time <= step.time);
        chain.steps.insert(position, step.clone());
        if chain.steps.len() > MAX_CHAIN_ACTIONS {
            chain.steps.remove(0);
            position = position.checked_sub(1)?;
        }

        let report = self.examine(&chain.steps, position, by_address, actor_is_principal)?;
        if only_malicious && !report.malicious {
            return None;
        }
        let end = report.steps.last().map_or(step.time, |last| last.time);
        chain.alert = Some((time_after(end, self.cooldown), report.malicious));
        chain.steps.clear();
        Some(report)
    }

    /// Examines the newest steps of a chain. `position` is the place of the new step.
    fn examine(
        &self,
        steps: &[Step],
        position: usize,
        by_address: bool,
        actor_is_principal: bool,
    ) -> Option<Report> {
        let run_of = |length: usize| -> Option<&[Step]> {
            let start = steps.len().checked_sub(length)?;
            let run = steps.get(start..)?;
            let mut actors: Vec<u64> = run.iter().map(|step| step.actor).collect();
            actors.sort_unstable();
            actors.dedup();
            // A chain of one principal from one address is the chain of that principal.
            let is_shared = !by_address || !actor_is_principal || actors.len() >= 2;
            (position >= start && is_shared && run.iter().any(|step| step.sensitive)).then_some(run)
        };
        let max_median = i64::try_from(self.config.max_median_gap_milliseconds).unwrap_or(i64::MAX);

        let short = run_of(self.config.min_actions).and_then(|run| {
            let gaps = gaps(run);
            let median = median(&gaps)?;
            (median <= max_median)
                .then(|| (run, Cadence::Short, median, coefficient_of_variation(&gaps)))
        });
        let regular = || {
            let run = run_of(self.config.min_actions.max(REGULARITY_MIN_ACTIONS))?;
            let gaps = gaps(run);
            let variation = coefficient_of_variation(&gaps)?;
            (variation <= self.config.max_coefficient_of_variation)
                .then(|| Some((run, Cadence::Regular, median(&gaps)?, Some(variation))))
                .flatten()
        };
        let (run, cadence, median_milliseconds, coefficient_of_variation) =
            short.or_else(regular)?;
        Some(Report {
            steps: run.to_vec(),
            cadence,
            median_milliseconds,
            coefficient_of_variation,
            by_address,
            malicious: !by_address && run.iter().any(|step| step.privileged),
        })
    }

    fn detection(&self, event: &Event, report: &Report) -> Detection {
        let (verdict, severity) = if report.malicious {
            (Verdict::Malicious, Severity::High)
        } else {
            (Verdict::Suspicious, Severity::Medium)
        };
        let count = report.steps.len();
        let mut entities: Vec<EntityRef> = Vec::new();
        let (subject, owner) = match event.actor.ip.filter(|_| report.by_address) {
            Some(ip) => {
                let ip = canonical_ip(ip);
                entities.push(ip_entity(ip));
                ("address", format!("address {ip}"))
            }
            None => (
                "principal",
                format!("principal {}", clean_text(&event.actor.id, MAX_LABEL_CHARS)),
            ),
        };
        if !report.by_address
            || matches!(
                event.actor.kind,
                EntityKind::User | EntityKind::ServicePrincipal | EntityKind::Application
            )
        {
            push_entity(&mut entities, event.actor.entity());
        }
        if !report.by_address {
            for ip in report.steps.iter().filter_map(|step| step.ip) {
                push_entity(&mut entities, ip_entity(ip));
            }
        }
        let cadence = match report.cadence {
            Cadence::Short => format!(
                "a median gap of {} milliseconds. The gaps are too short for a person.",
                report.median_milliseconds
            ),
            Cadence::Regular => format!(
                "regular gaps: the coefficient of variation is {:.3}. The gaps are too \
                 regular for a person.",
                report.coefficient_of_variation.unwrap_or_default()
            ),
        };
        let privileged = if report.malicious {
            " The chain includes a privileged change."
        } else {
            ""
        };
        let labels: Vec<&str> = report
            .steps
            .iter()
            .map(|step| step.label.as_str())
            .collect();
        let mut attributes = vec![
            ("subject", json!(subject)),
            ("actions", json!(labels)),
            ("distinct_actions", json!(count)),
            (
                "cadence",
                json!(match report.cadence {
                    Cadence::Short => "short_gaps",
                    Cadence::Regular => "regular_gaps",
                }),
            ),
            ("median_gap_milliseconds", json!(report.median_milliseconds)),
            ("window_seconds", json!(self.config.window_seconds)),
            (
                "privileged_change",
                json!(report.steps.iter().any(|step| step.privileged)),
            ),
        ];
        if let Some(variation) = report.coefficient_of_variation {
            attributes.push((
                "coefficient_of_variation",
                json!((variation * 1_000.0).round() / 1_000.0),
            ));
        }
        Finding {
            rule_id: MACHINE_CADENCE_RULE_ID,
            title: "Chain of sensitive actions at machine speed",
            description: format!(
                "The {owner} did {count} different actions with {cadence}{privileged}"
            ),
            severity,
            verdict,
            attack: vec![technique_in("execution", "T1059.009")],
            time: report.steps.last().map_or(event.time, |last| last.time),
            event_ids: report.steps.iter().map(|step| step.event_id).collect(),
            entities,
            attributes,
        }
        .into_detection(event)
    }
}

#[async_trait]
impl Detector for MachineCadence {
    fn id(&self) -> &str {
        MACHINE_CADENCE_RULE_ID
    }

    fn tier(&self) -> DetectionTier {
        DetectionTier::Deterministic
    }

    async fn inspect(&self, event: &Event) -> Result<Vec<Detection>> {
        Ok(self.evaluate(event).into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::AttackTechnique;
    use aegis_contracts::event::EventClass;

    use super::super::testing::{TENANT, actor, at, event};
    use super::*;

    const ADDRESS: &str = "203.0.113.51";
    const PRINCIPAL: &str = "sp-sync-helper";

    fn detector() -> MachineCadence {
        MachineCadence::new(MachineCadenceConfig::default()).unwrap()
    }

    /// One action of a service principal at `milliseconds` after the start of the log.
    fn step(sequence: u32, milliseconds: i64, action: &str) -> Event {
        step_of(sequence, milliseconds, action, PRINCIPAL, ADDRESS)
    }

    fn step_of(sequence: u32, milliseconds: i64, action: &str, id: &str, ip: &str) -> Event {
        event(
            sequence,
            at(milliseconds),
            EventClass::Other,
            action,
            actor(EntityKind::ServicePrincipal, id, ip),
        )
    }

    fn call(sequence: u32, milliseconds: i64, operation: &str) -> Event {
        step(sequence, milliseconds, action::API_CALL).with_attribute(attr::OPERATION, operation)
    }

    fn feed(detector: &MachineCadence, events: &[Event]) -> Vec<Detection> {
        events
            .iter()
            .filter_map(|event| detector.evaluate(event))
            .collect()
    }

    /// Four different actions, one sensitive, at the given times.
    fn chain(times: [i64; 4]) -> Vec<Event> {
        vec![
            step(1, times[0], action::SIGN_IN),
            step(2, times[1], action::USER_UPDATE),
            call(3, times[2], "GET /users"),
            call(4, times[3], "GET /groups"),
        ]
    }

    #[test]
    fn four_different_actions_with_short_gaps_are_a_suspicious_chain() {
        let detector = detector();
        let events = chain([0, 3_000, 7_000, 9_000]);
        // The chain is not complete before the fourth action.
        assert_eq!(feed(&detector, &events[..3]).len(), 0);
        let found = detector.evaluate(&events[3]).unwrap();
        assert_eq!(found.rule_id, MACHINE_CADENCE_RULE_ID);
        assert_eq!(found.verdict, Verdict::Suspicious);
        assert_eq!(found.severity, Severity::Medium);
        assert_eq!(found.tier, DetectionTier::Deterministic);
        assert_eq!(
            found.attack,
            [AttackTechnique::new("execution", "T1059.009", "Cloud API")]
        );
        assert_eq!(found.time, at(9_000));
        assert_eq!(
            found.event_ids,
            events.iter().map(|event| event.id).collect::<Vec<_>>()
        );
        assert_eq!(
            found.entities,
            [
                EntityRef::new(EntityKind::ServicePrincipal, PRINCIPAL),
                EntityRef::new(EntityKind::IpAddress, ADDRESS),
            ]
        );
        assert_eq!(found.tenant.as_deref(), Some(TENANT));
        assert_eq!(found.attributes["subject"], json!("principal"));
        assert_eq!(found.attributes["cadence"], json!("short_gaps"));
        assert_eq!(found.attributes["distinct_actions"], json!(4));
        // The gaps are 3, 4, and 2 seconds.
        assert_eq!(found.attributes["median_gap_milliseconds"], json!(3_000));
        assert_eq!(found.attributes["privileged_change"], json!(false));
        assert_eq!(
            found.attributes["actions"],
            json!([
                "sign_in",
                "user.update",
                "api.call GET /users",
                "api.call GET /groups"
            ])
        );
        assert_eq!(
            found.description,
            "The principal sp-sync-helper did 4 different actions with a median gap of 3000 \
             milliseconds. The gaps are too short for a person."
        );
    }

    #[test]
    fn a_chain_with_a_privileged_change_is_malicious() {
        let detector = detector();
        let mut events = chain([0, 3_000, 7_000, 9_000]);
        events[1] = step(2, 3_000, action::ROLE_ASSIGN).with_attribute(attr::PRIVILEGED, true);
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].verdict, Verdict::Malicious);
        assert_eq!(found[0].severity, Severity::High);
        assert_eq!(found[0].attributes["privileged_change"], json!(true));
        assert!(
            found[0]
                .description
                .ends_with("The chain includes a privileged change."),
            "{}",
            found[0].description
        );
    }

    #[test]
    fn a_privileged_flag_on_a_supporting_action_is_not_a_privileged_change() {
        let detector = detector();
        let mut events = chain([0, 3_000, 7_000, 9_000]);
        events[2] = call(3, 7_000, "GET /users").with_attribute(attr::PRIVILEGED, true);
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].verdict, Verdict::Suspicious);
    }

    #[test]
    fn a_chain_at_the_speed_of_a_person_gives_no_detection() {
        let detector = detector();
        // A person: 40, 75, and 20 seconds between the actions.
        assert_eq!(
            feed(&detector, &chain([0, 40_000, 115_000, 135_000])).len(),
            0
        );
        // The median gap of 5 seconds is the limit. One millisecond more is not a chain.
        let detector = self::detector();
        assert_eq!(feed(&detector, &chain([0, 5_001, 10_002, 15_003])).len(), 0);
        let detector = self::detector();
        assert_eq!(feed(&detector, &chain([0, 5_000, 10_000, 15_000])).len(), 1);
    }

    #[test]
    fn one_action_again_and_again_is_not_a_chain() {
        let detector = detector();
        let events: Vec<Event> = (0..50)
            .map(|index| step(index, i64::from(index) * 1_000, action::USER_UPDATE))
            .collect();
        assert_eq!(feed(&detector, &events).len(), 0);
        // The same API operation is one action. A different operation is a new action.
        let same: Vec<Event> = (0..50)
            .map(|index| call(100 + index, i64::from(index) * 1_000, "GET /users"))
            .collect();
        assert_eq!(feed(&detector, &same).len(), 0);
    }

    #[test]
    fn a_chain_with_no_sensitive_action_gives_no_detection() {
        let detector = detector();
        let events = vec![
            step(1, 0, action::SIGN_IN),
            call(2, 1_000, "GET /users"),
            call(3, 2_000, "GET /groups"),
            call(4, 3_000, "GET /devices"),
            call(5, 4_000, "GET /applications"),
        ];
        assert_eq!(feed(&detector, &events).len(), 0);
        // One sensitive action completes the chain.
        let found = detector.evaluate(&step(6, 5_000, action::SECRET_READ));
        assert_eq!(found.unwrap().attributes["distinct_actions"], json!(4));
    }

    #[test]
    fn an_action_that_is_not_in_the_lists_is_not_a_step() {
        let detector = detector();
        let events = vec![
            step(1, 0, action::USER_UPDATE),
            step(2, 1_000, action::NETWORK_CONNECT),
            step(3, 2_000, action::PROCESS_START),
            step(4, 3_000, action::HTTP_REQUEST),
        ];
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn a_failed_event_is_not_a_step() {
        let detector = detector();
        let mut events = chain([0, 3_000, 7_000, 9_000]);
        events[1].outcome = Outcome::Failure;
        // Three steps stay, and none of them is sensitive.
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn six_actions_with_regular_gaps_are_a_chain() {
        let detector = detector();
        // One action each 30 seconds. The median gap is not short.
        let actions = [
            action::USER_CREATE,
            action::USER_UPDATE,
            action::ROLE_ASSIGN,
            action::APP_CREATE,
            action::APP_CREDENTIAL_ADD,
            action::SECRET_READ,
        ];
        let events: Vec<Event> = actions
            .iter()
            .zip(0_u32..)
            .map(|(action, index)| step(index, i64::from(index) * 30_000, action))
            .collect();
        // Five regular actions are too few for the regularity test.
        assert_eq!(feed(&detector, &events[..5]).len(), 0);
        let found = detector.evaluate(&events[5]).unwrap();
        assert_eq!(found.attributes["cadence"], json!("regular_gaps"));
        assert_eq!(found.attributes["distinct_actions"], json!(6));
        assert_eq!(found.attributes["median_gap_milliseconds"], json!(30_000));
        assert_eq!(found.attributes["coefficient_of_variation"], json!(0.0));
        assert_eq!(found.event_ids.len(), 6);
        assert_eq!(
            found.description,
            "The principal sp-sync-helper did 6 different actions with regular gaps: the \
             coefficient of variation is 0.000. The gaps are too regular for a person."
        );
    }

    #[test]
    fn six_actions_with_gaps_that_are_not_regular_give_no_detection() {
        let detector = detector();
        let actions = [
            action::USER_CREATE,
            action::USER_UPDATE,
            action::ROLE_ASSIGN,
            action::APP_CREATE,
            action::APP_CREDENTIAL_ADD,
            action::SECRET_READ,
        ];
        // The gaps of a person: 20, 45, 31, 60, and 25 seconds.
        let times = [0, 20_000, 65_000, 96_000, 156_000, 181_000];
        let events: Vec<Event> = actions
            .iter()
            .zip(times)
            .zip(0_u32..)
            .map(|((action, time), index)| step(index, time, action))
            .collect();
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn the_statistics_of_the_gaps_are_correct() {
        let at_times = |times: &[i64]| -> Vec<Step> {
            times
                .iter()
                .map(|time| Step::of(&step(1, *time, action::USER_UPDATE), true))
                .collect()
        };
        let run = at_times(&[0, 1_000, 3_000, 6_000, 10_000]);
        let found = gaps(&run);
        assert_eq!(found.len(), 4);
        // The gaps are 1, 2, 3, and 4 seconds.
        assert_eq!(median(&found), Some(2_500));
        let variation = coefficient_of_variation(&found).unwrap();
        // The mean is 2.5, and the standard deviation is the square root of 1.25.
        assert!(
            (variation - 1.25_f64.sqrt() / 2.5).abs() < 1e-12,
            "{variation}"
        );

        let odd = gaps(&at_times(&[0, 5_000, 6_000, 16_000]));
        assert_eq!(median(&odd), Some(5_000));
        assert_eq!(median(&[]), None);
        assert_eq!(
            coefficient_of_variation(&gaps(&at_times(&[0, 1_000]))),
            None
        );
        // Events at one instant have a mean gap of zero.
        assert_eq!(coefficient_of_variation(&gaps(&at_times(&[0, 0, 0]))), None);
    }

    #[test]
    fn an_action_leaves_the_chain_after_the_window() {
        let detector = detector();
        // The window is 300 seconds. The first action is older than that at the end.
        let events = chain([0, 298_000, 299_000, 300_000]);
        assert_eq!(feed(&detector, &events).len(), 0);
        // A new first action completes the chain again.
        let found = detector.evaluate(&step(5, 301_000, action::SIGN_IN));
        assert_eq!(found.unwrap().event_ids.len(), 4);
    }

    #[test]
    fn one_chain_gives_one_detection_until_the_cooldown_ends() {
        let detector = detector();
        assert_eq!(feed(&detector, &chain([0, 1_000, 2_000, 3_000])).len(), 1);
        // The same actions again, and new actions, in the cooldown of 900 seconds.
        let more = vec![
            step(10, 10_000, action::SIGN_IN),
            step(11, 11_000, action::USER_UPDATE),
            call(12, 12_000, "GET /users"),
            call(13, 13_000, "GET /groups"),
            step(14, 14_000, action::USER_CREATE),
            step(15, 15_000, action::SECRET_READ),
        ];
        assert_eq!(feed(&detector, &more).len(), 0);
        // After the cooldown, a new chain gives a new detection.
        let later = vec![
            step(20, 903_000, action::SIGN_IN),
            step(21, 904_000, action::USER_UPDATE),
            call(22, 905_000, "GET /users"),
            call(23, 906_000, "GET /groups"),
        ];
        assert_eq!(feed(&detector, &later).len(), 1);
    }

    #[test]
    fn a_malicious_chain_in_the_cooldown_of_a_suspicious_detection_is_reported() {
        let detector = detector();
        let first = feed(&detector, &chain([0, 1_000, 2_000, 3_000]));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].verdict, Verdict::Suspicious);
        let privileged = vec![
            step(10, 10_000, action::SIGN_IN),
            step(11, 11_000, action::USER_CREATE),
            step(12, 12_000, action::ROLE_ASSIGN).with_attribute(attr::PRIVILEGED, true),
            step(13, 13_000, action::APP_CREDENTIAL_ADD),
        ];
        let second = feed(&detector, &privileged);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].verdict, Verdict::Malicious);
        // After a malicious detection, the cooldown stops all chains.
        let third = vec![
            step(20, 20_000, action::SIGN_IN),
            step(21, 21_000, action::USER_UPDATE),
            step(22, 22_000, action::ROLE_REMOVE).with_attribute(attr::PRIVILEGED, true),
            step(23, 23_000, action::SECRET_READ),
        ];
        assert_eq!(feed(&detector, &third).len(), 0);
    }

    #[test]
    fn each_principal_and_each_tenant_has_its_own_chain() {
        let detector = MachineCadence::new(MachineCadenceConfig {
            follow_addresses: false,
            ..MachineCadenceConfig::default()
        })
        .unwrap();
        let events = vec![
            step_of(1, 0, action::SIGN_IN, "sp-a", ADDRESS),
            step_of(2, 1_000, action::USER_UPDATE, "sp-b", ADDRESS),
            step_of(3, 2_000, action::USER_CREATE, "sp-a", ADDRESS),
            step_of(4, 3_000, action::SECRET_READ, "sp-b", ADDRESS),
        ];
        assert_eq!(feed(&detector, &events).len(), 0);

        // The same principal identifier in two tenants is two principals.
        let detector = self::detector();
        let mut events = chain([0, 1_000, 2_000, 3_000]);
        events[2].source.tenant = Some("tenant-2".to_owned());
        events[3].source.tenant = Some("tenant-2".to_owned());
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn an_address_that_two_principals_use_for_one_chain_is_suspicious() {
        let detector = detector();
        let events = [
            step_of(1, 0, action::SIGN_IN, "sp-a", ADDRESS),
            step_of(2, 1_000, action::USER_UPDATE, "sp-a", ADDRESS),
            step_of(3, 2_000, action::SIGN_OUT, "sp-a", ADDRESS),
            step_of(4, 3_000, action::ROLE_ASSIGN, "sp-b", ADDRESS)
                .with_attribute(attr::PRIVILEGED, true),
            step_of(5, 4_000, action::SECRET_READ, "sp-b", ADDRESS),
        ];
        // No principal has four actions. The address has four.
        assert_eq!(feed(&detector, &events[..4]).len(), 0);
        let found = detector.evaluate(&events[4]).unwrap();
        assert_eq!(found.attributes["subject"], json!("address"));
        // A chain of an address is suspicious, also with a privileged change.
        assert_eq!(found.verdict, Verdict::Suspicious);
        assert_eq!(found.attributes["privileged_change"], json!(true));
        assert_eq!(
            found.entities,
            [
                EntityRef::new(EntityKind::IpAddress, ADDRESS),
                EntityRef::new(EntityKind::ServicePrincipal, "sp-b"),
            ]
        );
        assert_eq!(
            found.event_ids,
            [events[0].id, events[1].id, events[3].id, events[4].id]
        );
        assert!(
            found
                .description
                .starts_with("The address 203.0.113.51 did 4 different actions"),
            "{}",
            found.description
        );
    }

    #[test]
    fn the_chain_of_one_principal_gives_one_detection_and_not_one_more_for_its_address() {
        let detector = detector();
        let mut events = chain([0, 1_000, 2_000, 3_000]);
        // More actions of the same principal from the same address.
        events.push(step(5, 4_000, action::USER_CREATE));
        events.push(step(6, 5_000, action::SECRET_READ));
        events.push(step(7, 6_000, action::APP_CREATE));
        events.push(step(8, 7_000, action::ROLE_REMOVE));
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].attributes["subject"], json!("principal"));
    }

    #[test]
    fn an_actor_that_is_not_a_principal_has_the_chain_of_its_address() {
        let detector = detector();
        let mut events = chain([0, 1_000, 2_000, 3_000]);
        for event in &mut events {
            event.actor.kind = EntityKind::Other;
            event.actor.id = "unknown".to_owned();
        }
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].attributes["subject"], json!("address"));
        assert_eq!(
            found[0].entities,
            [EntityRef::new(EntityKind::IpAddress, ADDRESS)]
        );
        // With no address, such an actor has no chain.
        let detector = self::detector();
        for event in &mut events {
            event.actor.ip = None;
        }
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn an_ignored_principal_gives_no_detection() {
        let detector = MachineCadence::new(MachineCadenceConfig {
            ignored_principals: vec![PRINCIPAL.to_owned()],
            ..MachineCadenceConfig::default()
        })
        .unwrap();
        assert_eq!(feed(&detector, &chain([0, 1_000, 2_000, 3_000])).len(), 0);
        // A different principal is not ignored.
        let other: Vec<Event> = chain([0, 1_000, 2_000, 3_000])
            .into_iter()
            .map(|mut event| {
                event.actor.id = "sp-other".to_owned();
                event
            })
            .collect();
        assert_eq!(feed(&detector, &other).len(), 1);
    }

    #[test]
    fn an_event_that_arrives_late_takes_its_place_in_the_chain() {
        let detector = detector();
        let events = chain([0, 3_000, 7_000, 9_000]);
        // The second action arrives last.
        let order = [&events[0], &events[2], &events[3], &events[1]];
        let found: Vec<Detection> = order
            .iter()
            .filter_map(|event| detector.evaluate(event))
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].event_ids,
            events.iter().map(|event| event.id).collect::<Vec<_>>()
        );
        assert_eq!(found[0].time, at(9_000));
    }

    #[test]
    fn events_at_the_ends_of_the_time_range_do_not_panic() {
        let detector = detector();
        let mut events = chain([0, 1_000, 2_000, 3_000]);
        events[0].time = DateTime::<Utc>::MIN_UTC;
        events[3].time = DateTime::<Utc>::MAX_UTC;
        assert_eq!(feed(&detector, &events).len(), 0);
        // A second principal, from a different address, with all events at the end of the
        // range. The cooldown of its detection ends after the end of the range.
        let mut all_at_the_end = chain([0, 1_000, 2_000, 3_000]);
        for event in &mut all_at_the_end {
            event.time = DateTime::<Utc>::MAX_UTC;
            event.actor = actor(EntityKind::ServicePrincipal, "sp-end", "203.0.113.99");
        }
        let found = feed(&detector, &all_at_the_end);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].time, DateTime::<Utc>::MAX_UTC);
        assert_eq!(found[0].attributes["median_gap_milliseconds"], json!(0));
    }

    #[test]
    fn the_state_is_limited() {
        let detector = MachineCadence::new(MachineCadenceConfig {
            max_tracked_keys: 8,
            ..MachineCadenceConfig::default()
        })
        .unwrap();
        for index in 0..1_000_u32 {
            let event = step_of(
                index,
                i64::from(index),
                action::USER_UPDATE,
                &format!("sp-{index}"),
                &format!("203.0.113.{}", index % 250),
            );
            assert_eq!(detector.evaluate(&event), None);
            assert!(lock(&detector.state).len() <= 8);
        }

        // One principal with many different API operations keeps a limited chain.
        let detector = self::detector();
        for index in 0..200_u32 {
            let _ = detector.evaluate(&call(
                index,
                i64::from(index) * 20_000,
                &format!("GET /{index}"),
            ));
        }
        let state = lock(&detector.state);
        assert_eq!(state.len(), 2);
        assert!(
            state
                .values()
                .all(|chain| chain.steps.len() <= MAX_CHAIN_ACTIONS)
        );
    }

    #[test]
    fn a_detector_that_is_not_enabled_gives_no_detection() {
        let detector = MachineCadence::new(MachineCadenceConfig {
            enabled: false,
            ..MachineCadenceConfig::default()
        })
        .unwrap();
        assert_eq!(feed(&detector, &chain([0, 1_000, 2_000, 3_000])).len(), 0);
    }

    #[test]
    fn settings_that_are_not_valid_are_errors() {
        let base = MachineCadenceConfig::default;
        let cases = [
            (
                MachineCadenceConfig {
                    window_seconds: 0,
                    ..base()
                },
                "machine_cadence.window_seconds must be 1 or more, but it is 0",
            ),
            (
                MachineCadenceConfig {
                    min_actions: 1,
                    ..base()
                },
                "machine_cadence.min_actions must be 2 or more, but it is 1",
            ),
            (
                MachineCadenceConfig {
                    min_actions: 17,
                    ..base()
                },
                "machine_cadence.min_actions must be 16 or less, but it is 17",
            ),
            (
                MachineCadenceConfig {
                    max_coefficient_of_variation: f64::NAN,
                    ..base()
                },
                "machine_cadence.max_coefficient_of_variation must be a number of 0 or more, \
                 but it is NaN",
            ),
            (
                MachineCadenceConfig {
                    max_coefficient_of_variation: -0.1,
                    ..base()
                },
                "machine_cadence.max_coefficient_of_variation must be a number of 0 or more, \
                 but it is -0.1",
            ),
            (
                MachineCadenceConfig {
                    sensitive_actions: Vec::new(),
                    ..base()
                },
                "machine_cadence.sensitive_actions is empty; set enabled = false to stop the \
                 detector",
            ),
            (
                MachineCadenceConfig {
                    supporting_actions: vec![" ".to_owned()],
                    ..base()
                },
                "machine_cadence: an action name is empty",
            ),
            (
                MachineCadenceConfig {
                    max_tracked_keys: 0,
                    ..base()
                },
                "machine_cadence.max_tracked_keys must be 1 or more, but it is 0",
            ),
            (
                MachineCadenceConfig {
                    cooldown_seconds: u64::MAX,
                    ..base()
                },
                "machine_cadence.cooldown_seconds is too large: 18446744073709551615",
            ),
        ];
        for (config, expected) in cases {
            let error = MachineCadence::new(config).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!("detector configuration: {expected}")
            );
        }
    }

    #[test]
    fn the_settings_change_what_is_a_chain() {
        // Two actions are a chain, and all gaps of 60 seconds or less are short.
        let detector = MachineCadence::new(MachineCadenceConfig {
            min_actions: 2,
            max_median_gap_milliseconds: 60_000,
            sensitive_actions: vec![action::NETWORK_CONNECT.to_owned()],
            supporting_actions: vec![action::PROCESS_START.to_owned()],
            ..MachineCadenceConfig::default()
        })
        .unwrap();
        let events = vec![
            step(1, 0, action::PROCESS_START),
            step(2, 60_000, action::NETWORK_CONNECT),
        ];
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].attributes["median_gap_milliseconds"],
            json!(60_000)
        );
        // The default sensitive actions are no longer steps.
        let detector2 = MachineCadence::new(MachineCadenceConfig {
            sensitive_actions: vec![action::NETWORK_CONNECT.to_owned()],
            ..MachineCadenceConfig::default()
        })
        .unwrap();
        assert_eq!(feed(&detector2, &chain([0, 1_000, 2_000, 3_000])).len(), 0);
    }

    #[test]
    fn text_from_the_event_is_cleaned_and_limited_in_the_detection() {
        let detector = detector();
        let mut events = chain([0, 1_000, 2_000, 3_000]);
        let long = format!("GET /\u{1b}[31m{}", "a".repeat(500));
        events[3] = call(4, 3_000, &long);
        for event in &mut events {
            event.actor.id = format!("sp\n{}", "b".repeat(300));
        }
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        let actions = found[0].attributes["actions"].as_array().unwrap();
        let last = actions[3].as_str().unwrap();
        assert!(!last.contains('\u{1b}'), "{last:?}");
        assert_eq!(last.chars().count(), "api.call ".len() + 64);
        assert!(!found[0].description.contains('\n'));
        assert!(found[0].description.chars().count() < 250);
    }

    #[tokio::test]
    async fn the_detector_contract_returns_the_detection() {
        let detector = detector();
        assert_eq!(detector.id(), MACHINE_CADENCE_RULE_ID);
        assert_eq!(detector.tier(), DetectionTier::Deterministic);
        let events = chain([0, 1_000, 2_000, 3_000]);
        let mut found = Vec::new();
        for event in &events {
            found.extend(detector.inspect(event).await.unwrap());
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, MACHINE_CADENCE_RULE_ID);
    }
}
