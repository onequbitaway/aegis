//! The endpoint-probe detector.

use std::net::IpAddr;
use std::sync::Mutex;

use aegis_contracts::common::{EntityKind, EntityRef, EventId, Severity};
use aegis_contracts::event::{Event, action, attr};
use aegis_contracts::{Detection, DetectionTier, Detector, Result, Verdict};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Finding, Tracked, at_least, seconds, tenant_key, text_key};
use crate::attack::technique_in;
use crate::common::{
    canonical_ip, clean_text, default_verdict, digest128, fingerprint_entity, fingerprint_token,
    ip_entity, lock, push_entity, time_after, time_before,
};
use crate::error::DetectError;

/// The rule identifier of an endpoint-probe detection.
pub const ENDPOINT_PROBE_RULE_ID: &str = "aegis.velocity.endpoint_probe";

/// The rule identifier of a detection for a request to a decoy path.
pub const DECOY_PATH_RULE_ID: &str = "aegis.velocity.decoy_path";

/// The largest value of `distinct_path_threshold`. It limits the state of one client.
pub const MAX_DISTINCT_PATH_THRESHOLD: usize = 1_000;

/// The largest number of events that one detection names.
const MAX_REPORTED_EVENTS: usize = 100;

/// The number of paths that a detection keeps as examples.
const MAX_SAMPLE_PATHS: usize = 5;

/// The number of characters of a path or a user agent that a detection keeps.
const MAX_TEXT_CHARS: usize = 160;

/// The settings of [`EndpointProbe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EndpointProbeConfig {
    /// Set to `false` to stop the detector.
    pub enabled: bool,
    /// The length of the sliding window in seconds.
    pub window_seconds: u64,
    /// The number of different missing paths from one client in the window that is a
    /// probe.
    pub distinct_path_threshold: usize,
    /// The HTTP status codes that show a path that does not exist.
    pub missing_statuses: Vec<u16>,
    /// The decoy paths. No approved client asks for them. A path that ends with `*`
    /// matches each path that starts with the text before the `*`. The comparison ignores
    /// ASCII case and a `/` at the end.
    pub decoy_paths: Vec<String>,
    /// The severity of a detection for a decoy path. The severities `high` and `critical`
    /// make the detection `malicious`.
    pub decoy_path_severity: Severity,
    /// The time in seconds after a detection in which the detector reports no more
    /// detections of the same type for the same client.
    pub cooldown_seconds: u64,
    /// The largest number of clients for which the detector keeps state.
    pub max_tracked_clients: usize,
}

impl Default for EndpointProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: 60,
            distinct_path_threshold: 20,
            missing_statuses: vec![404, 410],
            decoy_paths: Vec::new(),
            decoy_path_severity: Severity::Medium,
            cooldown_seconds: 900,
            max_tracked_clients: 100_000,
        }
    }
}

/// A decoy path of the configuration, in the form that the detector compares.
struct DecoyPath {
    /// The text of the configuration.
    configured: String,
    /// The path in lower case, with no `*` and no `/` at the end.
    normal: String,
    is_prefix: bool,
}

impl DecoyPath {
    /// `full` is the path in lower case with no query. `normal` is `full` with no `/` at
    /// the end.
    fn matches(&self, full: &str, normal: &str) -> bool {
        if self.is_prefix {
            full.starts_with(&self.normal)
        } else {
            normal == self.normal
        }
    }
}

/// Returns a path in lower case, with no query and no fragment.
fn full_path(path: &str) -> String {
    path.split(['?', '#'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_ascii_lowercase()
}

/// Returns a path in lower case, with no query, no fragment, and no `/` at the end.
fn normal_path(path: &str) -> String {
    let path = full_path(path);
    match path.trim_end_matches('/') {
        "" if !path.is_empty() => "/".to_owned(),
        trimmed => trimmed.to_owned(),
    }
}

/// The client of a request: its address, or its fingerprint if it has no address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Client {
    Address(IpAddr),
    Fingerprint(u128),
}

struct Missing {
    /// A number that identifies the path.
    path: u64,
    time: DateTime<Utc>,
    event_id: EventId,
}

/// A detection that the detector reported for one client.
struct Alert {
    /// The first instant after the cooldown.
    until: DateTime<Utc>,
    /// `true` if the detector reported a decoy path in this cooldown.
    decoy_reported: bool,
    /// `true` if the detector reported a probe in this cooldown.
    probe_reported: bool,
}

#[derive(Default)]
struct ClientState {
    /// The requests for missing paths in the window, oldest first. Each path is there one
    /// time.
    missing: Vec<Missing>,
    /// The first paths of `missing`, as text for the detection.
    samples: Vec<String>,
    alert: Option<Alert>,
}

/// Finds one client that probes the web and API endpoints of the operator.
///
/// The detector examines `http.request` events. The client is the address of the actor.
/// If the event has no address, the client is the attribute `client_fingerprint`.
///
/// - **Probe**: one client asks for `distinct_path_threshold` different paths that do not
///   exist (the attribute `http_status` is in `missing_statuses`) in the window. The
///   technique is `T1595.003` (Active Scanning: Wordlist Scanning). The detection is
///   `suspicious`, because scanners are frequent.
/// - **Decoy path**: one client asks for a path of `decoy_paths`. One request is
///   sufficient. The technique is `T1595` (Active Scanning).
///
/// The detector makes ONE detection of each type for one client, and then no more of that
/// type until the cooldown ends. It does not make one detection for each request.
pub struct EndpointProbe {
    config: EndpointProbeConfig,
    window: TimeDelta,
    cooldown: TimeDelta,
    decoy_paths: Vec<DecoyPath>,
    state: Mutex<Tracked<(u64, Client), ClientState>>,
}

impl EndpointProbe {
    /// Makes the detector.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Config`] if the window is zero, `distinct_path_threshold` is
    /// less than 2 or more than [`MAX_DISTINCT_PATH_THRESHOLD`], a status code is not from
    /// 100 to 599, a decoy path does not start with `/`, or `max_tracked_clients` is zero.
    pub fn new(config: EndpointProbeConfig) -> std::result::Result<Self, DetectError> {
        let prefix = "endpoint_probe";
        at_least(
            &format!("{prefix}.window_seconds"),
            usize::try_from(config.window_seconds).unwrap_or(usize::MAX),
            1,
        )?;
        at_least(
            &format!("{prefix}.distinct_path_threshold"),
            config.distinct_path_threshold,
            2,
        )?;
        if config.distinct_path_threshold > MAX_DISTINCT_PATH_THRESHOLD {
            return Err(DetectError::Config(format!(
                "{prefix}.distinct_path_threshold must be {MAX_DISTINCT_PATH_THRESHOLD} or \
                 less, but it is {}",
                config.distinct_path_threshold
            )));
        }
        if let Some(status) = config
            .missing_statuses
            .iter()
            .find(|status| !(100..=599).contains(*status))
        {
            return Err(DetectError::Config(format!(
                "{prefix}.missing_statuses must hold status codes from 100 to 599, but it \
                 holds {status}"
            )));
        }
        let mut decoy_paths = Vec::with_capacity(config.decoy_paths.len());
        for configured in &config.decoy_paths {
            let text = configured.trim();
            let (body, is_prefix) = match text.strip_suffix('*') {
                Some(body) => (body, true),
                None => (text, false),
            };
            if !body.starts_with('/') || body.contains('*') {
                return Err(DetectError::Config(format!(
                    "{prefix}.decoy_paths: the path {configured:?} must start with \"/\" and \
                     can have one \"*\", at the end"
                )));
            }
            let normal = if is_prefix {
                body.to_ascii_lowercase()
            } else {
                normal_path(body)
            };
            if is_prefix && normal == "/" {
                return Err(DetectError::Config(format!(
                    "{prefix}.decoy_paths: the path {configured:?} matches all paths"
                )));
            }
            decoy_paths.push(DecoyPath {
                configured: text.to_owned(),
                normal,
                is_prefix,
            });
        }
        at_least(
            &format!("{prefix}.max_tracked_clients"),
            config.max_tracked_clients,
            1,
        )?;
        Ok(Self {
            window: seconds(&format!("{prefix}.window_seconds"), config.window_seconds)?,
            cooldown: seconds(
                &format!("{prefix}.cooldown_seconds"),
                config.cooldown_seconds,
            )?,
            decoy_paths,
            state: Mutex::new(Tracked::new(config.max_tracked_clients)),
            config,
        })
    }

    /// Examines one event. Returns a detection if the event completes a probe, or if it
    /// is the first request of the client for a decoy path.
    #[must_use]
    pub fn evaluate(&self, event: &Event) -> Option<Detection> {
        if !self.config.enabled || event.action != action::HTTP_REQUEST {
            return None;
        }
        let client = match event.actor.ip.map(canonical_ip) {
            Some(ip) => Client::Address(ip),
            None => {
                let token = fingerprint_token(event.attribute_str(attr::CLIENT_FINGERPRINT)?)?;
                Client::Fingerprint(digest128(&[token.as_bytes()]))
            }
        };
        let raw_path = event.attribute_str(attr::HTTP_PATH)?;
        let full = full_path(raw_path);
        let path = normal_path(raw_path);
        if path.is_empty() {
            return None;
        }
        let key = (tenant_key(event), client);
        match self
            .decoy_paths
            .iter()
            .find(|decoy| decoy.matches(&full, &path))
        {
            Some(decoy) => self.decoy(event, key, decoy, raw_path),
            None => self.missing(event, key, &path, raw_path),
        }
    }

    /// Returns the end of a cooldown that starts at `time`, or the end of the current
    /// cooldown if that is later.
    fn cooldown_end(&self, alert: Option<&Alert>, time: DateTime<Utc>) -> DateTime<Utc> {
        let end = time_after(time, self.cooldown);
        alert.map_or(end, |alert| alert.until.max(end))
    }

    fn decoy(
        &self,
        event: &Event,
        key: (u64, Client),
        decoy: &DecoyPath,
        raw_path: &str,
    ) -> Option<Detection> {
        let mut tracked = lock(&self.state);
        let state = tracked.upsert(key, event.time, ClientState::default);
        let active = state
            .alert
            .as_ref()
            .filter(|alert| event.time < alert.until);
        if active.is_some_and(|alert| alert.decoy_reported) {
            return None;
        }
        state.alert = Some(Alert {
            until: self.cooldown_end(active, event.time),
            decoy_reported: true,
            probe_reported: active.is_some_and(|alert| alert.probe_reported),
        });
        drop(tracked);

        let severity = self.config.decoy_path_severity;
        let mut attributes = self.client_attributes(event);
        attributes.push(("decoy_path", json!(decoy.configured)));
        attributes.push((attr::HTTP_PATH, json!(clean_text(raw_path, MAX_TEXT_CHARS))));
        if let Some(status) = status_of(event) {
            attributes.push((attr::HTTP_STATUS, json!(status)));
        }
        Some(
            Finding {
                rule_id: DECOY_PATH_RULE_ID,
                title: "Client asked for a decoy path",
                description: format!(
                    "The client {} asked for the decoy path {}. No approved client uses \
                     this path.",
                    client_text(event),
                    decoy.configured
                ),
                severity,
                verdict: default_verdict(severity),
                attack: vec![technique_in("reconnaissance", "T1595")],
                time: event.time,
                event_ids: vec![event.id],
                entities: client_entities(event),
                attributes,
            }
            .into_detection(event),
        )
    }

    fn missing(
        &self,
        event: &Event,
        key: (u64, Client),
        path: &str,
        raw_path: &str,
    ) -> Option<Detection> {
        let status = status_of(event)?;
        if !self.config.missing_statuses.contains(&status) {
            return None;
        }
        let mut tracked = lock(&self.state);
        let state = tracked.upsert(key, event.time, ClientState::default);
        if let Some(alert) = &state.alert {
            if event.time >= alert.until {
                state.alert = None;
            } else if alert.probe_reported {
                return None;
            }
        }

        let newest = state
            .missing
            .last()
            .map_or(event.time, |last| last.time.max(event.time));
        let horizon = time_before(newest, self.window);
        if state.missing.iter().any(|known| known.time <= horizon) {
            state.missing.retain(|known| known.time > horizon);
            // The examples are the first paths of the window. They start again.
            state.samples.clear();
        }
        let path_key = text_key(path);
        if event.time <= horizon || state.missing.iter().any(|known| known.path == path_key) {
            return None;
        }
        state.missing.push(Missing {
            path: path_key,
            time: event.time,
            event_id: event.id,
        });
        if state.samples.len() < MAX_SAMPLE_PATHS {
            state.samples.push(clean_text(raw_path, MAX_TEXT_CHARS));
        }
        let paths = state.missing.len();
        if paths < self.config.distinct_path_threshold {
            return None;
        }

        let event_ids: Vec<EventId> = state
            .missing
            .iter()
            .rev()
            .take(MAX_REPORTED_EVENTS)
            .rev()
            .map(|known| known.event_id)
            .collect();
        let samples = std::mem::take(&mut state.samples);
        state.missing.clear();
        state.alert = Some(Alert {
            until: self.cooldown_end(state.alert.as_ref(), event.time),
            decoy_reported: state
                .alert
                .as_ref()
                .is_some_and(|alert| alert.decoy_reported),
            probe_reported: true,
        });
        drop(tracked);

        let mut attributes = self.client_attributes(event);
        attributes.push(("distinct_paths", json!(paths)));
        attributes.push(("window_seconds", json!(self.config.window_seconds)));
        attributes.push(("sample_paths", json!(samples)));
        Some(
            Finding {
                rule_id: ENDPOINT_PROBE_RULE_ID,
                title: "Client probes for endpoints that do not exist",
                description: format!(
                    "The client {} asked for {paths} different paths that do not exist in \
                     {} seconds.",
                    client_text(event),
                    self.config.window_seconds
                ),
                severity: Severity::Medium,
                verdict: Verdict::Suspicious,
                attack: vec![technique_in("reconnaissance", "T1595.003")],
                time: event.time,
                event_ids,
                entities: client_entities(event),
                attributes,
            }
            .into_detection(event),
        )
    }

    /// Returns the attributes that name the client of an event.
    fn client_attributes(&self, event: &Event) -> Vec<(&'static str, Value)> {
        let mut attributes = vec![("client", json!(client_text(event)))];
        if let Some(token) = event
            .attribute_str(attr::CLIENT_FINGERPRINT)
            .and_then(fingerprint_token)
        {
            attributes.push((attr::CLIENT_FINGERPRINT, json!(token)));
        }
        if let Some(user_agent) = event.actor.user_agent.as_deref() {
            attributes.push(("user_agent", json!(clean_text(user_agent, MAX_TEXT_CHARS))));
        }
        attributes
    }
}

/// Returns the attribute `http_status` as a status code. The value can be a number or a
/// text with a number.
fn status_of(event: &Event) -> Option<u16> {
    match event.attributes.get(attr::HTTP_STATUS)? {
        Value::Number(number) => number.as_u64().and_then(|code| u16::try_from(code).ok()),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Returns the text that names the client of an event in a description.
fn client_text(event: &Event) -> String {
    match event.actor.ip {
        Some(ip) => canonical_ip(ip).to_string(),
        None => "with no address".to_owned(),
    }
}

/// Returns the entities of the client: the address, the fingerprint, and the actor if it
/// is a principal.
///
/// An actor that is not a principal is not an entity. Many clients share such an actor,
/// for example `anonymous`, and it would link incidents that are not related.
fn client_entities(event: &Event) -> Vec<EntityRef> {
    let mut entities = Vec::with_capacity(3);
    if let Some(ip) = event.actor.ip {
        entities.push(ip_entity(ip));
    }
    if let Some(fingerprint) = fingerprint_entity(event) {
        push_entity(&mut entities, fingerprint);
    }
    if matches!(
        event.actor.kind,
        EntityKind::User | EntityKind::ServicePrincipal | EntityKind::Application
    ) {
        push_entity(&mut entities, event.actor.entity());
    }
    entities
}

#[async_trait]
impl Detector for EndpointProbe {
    fn id(&self) -> &str {
        ENDPOINT_PROBE_RULE_ID
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
    use aegis_contracts::event::{Actor, EventClass};

    use super::super::testing::{TENANT, actor, at, event};
    use super::*;

    const CLIENT: &str = "203.0.113.80";

    fn config() -> EndpointProbeConfig {
        EndpointProbeConfig {
            window_seconds: 10,
            distinct_path_threshold: 5,
            cooldown_seconds: 60,
            decoy_paths: vec!["/.env".to_owned(), "/backup/*".to_owned()],
            ..EndpointProbeConfig::default()
        }
    }

    fn detector() -> EndpointProbe {
        EndpointProbe::new(config()).unwrap()
    }

    fn request_from(sequence: u32, milliseconds: i64, ip: &str, path: &str, status: u16) -> Event {
        event(
            sequence,
            at(milliseconds),
            EventClass::NetworkActivity,
            action::HTTP_REQUEST,
            actor(EntityKind::Other, "anonymous", ip).with_user_agent("probe-tool/1.0"),
        )
        .with_attribute(attr::HTTP_METHOD, "GET")
        .with_attribute(attr::HTTP_PATH, path)
        .with_attribute(attr::HTTP_STATUS, status)
    }

    fn request(sequence: u32, milliseconds: i64, path: &str, status: u16) -> Event {
        request_from(sequence, milliseconds, CLIENT, path, status)
    }

    /// Requests from one client for different missing paths, one each 100 milliseconds.
    fn missing(first_sequence: u32, start: i64, count: u32) -> Vec<Event> {
        (0..count)
            .map(|index| {
                request(
                    first_sequence + index,
                    start + i64::from(index) * 100,
                    &format!("/missing/{}", first_sequence + index),
                    404,
                )
            })
            .collect()
    }

    fn feed(detector: &EndpointProbe, events: &[Event]) -> Vec<Detection> {
        events
            .iter()
            .filter_map(|event| detector.evaluate(event))
            .collect()
    }

    #[test]
    fn many_different_missing_paths_from_one_client_give_one_detection() {
        let detector = detector();
        let events = missing(0, 0, 50);
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        let probe = &found[0];
        assert_eq!(probe.rule_id, ENDPOINT_PROBE_RULE_ID);
        assert_eq!(probe.verdict, Verdict::Suspicious);
        assert_eq!(probe.severity, Severity::Medium);
        assert_eq!(probe.tier, DetectionTier::Deterministic);
        assert_eq!(
            probe.attack,
            [AttackTechnique::new(
                "reconnaissance",
                "T1595.003",
                "Wordlist Scanning"
            )]
        );
        // The fifth path completes the probe.
        assert_eq!(probe.time, at(400));
        assert_eq!(
            probe.event_ids,
            events[..5].iter().map(|event| event.id).collect::<Vec<_>>()
        );
        // The actor `anonymous` is not an entity: many clients share it.
        assert_eq!(
            probe.entities,
            [EntityRef::new(EntityKind::IpAddress, CLIENT)]
        );
        assert_eq!(probe.tenant.as_deref(), Some(TENANT));
        assert_eq!(probe.attributes["client"], json!(CLIENT));
        assert_eq!(probe.attributes["distinct_paths"], json!(5));
        assert_eq!(probe.attributes["window_seconds"], json!(10));
        assert_eq!(probe.attributes["user_agent"], json!("probe-tool/1.0"));
        assert_eq!(
            probe.attributes["sample_paths"],
            json!([
                "/missing/0",
                "/missing/1",
                "/missing/2",
                "/missing/3",
                "/missing/4"
            ])
        );
        assert_eq!(
            probe.description,
            "The client 203.0.113.80 asked for 5 different paths that do not exist in 10 \
             seconds."
        );
    }

    #[test]
    fn requests_for_paths_that_exist_give_no_detection() {
        let detector = detector();
        let one_path: Vec<Event> = (0..50)
            .map(|index| request(index, i64::from(index) * 100, "/index.html", 200))
            .collect();
        assert_eq!(feed(&detector, &one_path).len(), 0);
        // Many different paths that exist are also not a probe.
        let many: Vec<Event> = (0..50)
            .map(|index| {
                request(
                    100 + index,
                    i64::from(index) * 100,
                    &format!("/page/{index}"),
                    200,
                )
            })
            .collect();
        assert_eq!(feed(&detector, &many).len(), 0);
        // The status codes 401, 403, and 500 do not show a path that does not exist.
        for (index, status) in [(200_u32, 401_u16), (201, 403), (202, 500), (203, 301)] {
            let events: Vec<Event> = (0..10)
                .map(|step| {
                    request(
                        index * 100 + step,
                        i64::from(step) * 100,
                        &format!("/secret/{step}"),
                        status,
                    )
                })
                .collect();
            assert_eq!(feed(&detector, &events).len(), 0, "{status}");
        }
    }

    #[test]
    fn one_missing_path_again_and_again_gives_no_detection() {
        let detector = detector();
        let events: Vec<Event> = (0..50)
            .map(|index| request(index, i64::from(index) * 100, "/favicon.ico", 404))
            .collect();
        assert_eq!(feed(&detector, &events).len(), 0);
        // The query, the case, and a slash at the end do not make a different path.
        let forms = [
            "/Favicon.ico",
            "/favicon.ico?v=2",
            "/favicon.ico/",
            "/favicon.ico#top",
        ];
        let events: Vec<Event> = forms
            .iter()
            .zip(100_u32..)
            .map(|(path, sequence)| request(sequence, 5_000, path, 404))
            .collect();
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn the_status_gone_and_a_status_as_text_count_as_missing() {
        let detector = detector();
        let mut events = missing(0, 0, 5);
        events[1]
            .attributes
            .insert(attr::HTTP_STATUS.to_owned(), json!(410));
        events[2]
            .attributes
            .insert(attr::HTTP_STATUS.to_owned(), json!("404"));
        assert_eq!(feed(&detector, &events).len(), 1);
        // An event with no status, or with a status that is not a code, is not counted.
        let detector = self::detector();
        let mut events = missing(0, 0, 5);
        events[1].attributes.remove(attr::HTTP_STATUS);
        events[2]
            .attributes
            .insert(attr::HTTP_STATUS.to_owned(), json!("not found"));
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn missing_paths_that_are_slow_give_no_detection() {
        let detector = detector();
        // One missing path each 3 seconds: at most four are in the window of 10 seconds.
        let events: Vec<Event> = (0..40)
            .map(|index| {
                request(
                    index,
                    i64::from(index) * 3_000,
                    &format!("/old/{index}"),
                    404,
                )
            })
            .collect();
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn each_client_and_each_tenant_has_its_own_count() {
        let detector = detector();
        let events: Vec<Event> = (0..40_u32)
            .map(|index| {
                request_from(
                    index,
                    i64::from(index) * 100,
                    &format!("203.0.113.{}", 100 + index % 10),
                    &format!("/missing/{index}"),
                    404,
                )
            })
            .collect();
        // Each of the ten clients asked for four paths.
        assert_eq!(feed(&detector, &events).len(), 0);

        let detector = self::detector();
        let mut events = missing(0, 0, 5);
        events[4].source.tenant = Some("tenant-2".to_owned());
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn one_probe_gives_one_detection_until_the_cooldown_ends() {
        let detector = detector();
        assert_eq!(feed(&detector, &missing(0, 0, 200)).len(), 1);
        // The cooldown is 60 seconds from the detection at 0.4 seconds.
        assert_eq!(feed(&detector, &missing(1_000, 30_000, 50)).len(), 0);
        let again = feed(&detector, &missing(2_000, 61_000, 50));
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].time, at(61_400));
    }

    #[test]
    fn one_request_for_a_decoy_path_gives_one_detection() {
        let detector = detector();
        let hit = request(1, 0, "/.env", 404);
        let found = detector.evaluate(&hit).unwrap();
        assert_eq!(found.rule_id, DECOY_PATH_RULE_ID);
        assert_eq!(found.verdict, Verdict::Suspicious);
        assert_eq!(found.severity, Severity::Medium);
        assert_eq!(
            found.attack,
            [AttackTechnique::new(
                "reconnaissance",
                "T1595",
                "Active Scanning"
            )]
        );
        assert_eq!(found.event_ids, [hit.id]);
        assert_eq!(
            found.entities,
            [EntityRef::new(EntityKind::IpAddress, CLIENT)]
        );
        assert_eq!(found.attributes["decoy_path"], json!("/.env"));
        assert_eq!(found.attributes["http_path"], json!("/.env"));
        assert_eq!(found.attributes["http_status"], json!(404));
        assert_eq!(found.attributes["user_agent"], json!("probe-tool/1.0"));
        assert_eq!(
            found.description,
            "The client 203.0.113.80 asked for the decoy path /.env. No approved client uses \
             this path."
        );
        // More requests of the client for decoy paths give no more detections.
        let more = vec![
            request(2, 1_000, "/.env", 404),
            request(3, 2_000, "/backup/db.sql", 200),
            request(4, 3_000, "/.ENV?x=1", 404),
        ];
        assert_eq!(feed(&detector, &more).len(), 0);
        // After the cooldown, a request gives a new detection.
        let later = detector.evaluate(&request(5, 61_000, "/backup/", 200));
        assert_eq!(later.unwrap().attributes["decoy_path"], json!("/backup/*"));
    }

    #[test]
    fn a_decoy_path_matches_with_any_status_and_a_near_path_does_not_match() {
        for (sequence, path, status) in [
            (1_u32, "/.env", 200_u16),
            (2, "/.Env/", 403),
            (3, "/backup/2024/db.sql", 404),
            (4, "/BACKUP/x", 500),
        ] {
            let detector = detector();
            let found = detector.evaluate(&request(sequence, 0, path, status));
            assert_eq!(
                found.map(|found| found.rule_id),
                Some(DECOY_PATH_RULE_ID.to_owned()),
                "{path}"
            );
        }
        for (sequence, path) in [
            (1_u32, "/.env.example"),
            (2, "/app/.env"),
            (3, "/backup"),
            (4, "/backups/x"),
            (5, "/"),
        ] {
            let detector = detector();
            assert_eq!(
                detector.evaluate(&request(sequence, 0, path, 200)),
                None,
                "{path}"
            );
        }
    }

    #[test]
    fn a_decoy_path_in_the_cooldown_of_a_probe_is_reported_one_time() {
        let detector = detector();
        assert_eq!(feed(&detector, &missing(0, 0, 10)).len(), 1);
        let hit = detector.evaluate(&request(100, 5_000, "/.env", 404));
        assert_eq!(hit.unwrap().rule_id, DECOY_PATH_RULE_ID);
        assert_eq!(detector.evaluate(&request(101, 6_000, "/.env", 404)), None);
        // A probe in the cooldown of a decoy path is also reported one time.
        let detector = self::detector();
        let hit = detector.evaluate(&request(1, 0, "/.env", 404));
        assert_eq!(hit.unwrap().rule_id, DECOY_PATH_RULE_ID);
        let probes = feed(&detector, &missing(10, 1_000, 30));
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].rule_id, ENDPOINT_PROBE_RULE_ID);
    }

    #[test]
    fn the_severity_setting_makes_a_decoy_path_malicious() {
        let detector = EndpointProbe::new(EndpointProbeConfig {
            decoy_path_severity: Severity::High,
            ..config()
        })
        .unwrap();
        let found = detector.evaluate(&request(1, 0, "/.env", 404)).unwrap();
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.verdict, Verdict::Malicious);
    }

    #[test]
    fn a_client_with_no_address_is_its_fingerprint() {
        let detector = detector();
        let with_fingerprint = |sequence: u32, fingerprint: &str| {
            let mut event = request(sequence, i64::from(sequence) * 100, "/x", 404)
                .with_attribute(attr::HTTP_PATH, format!("/missing/{sequence}"))
                .with_attribute(attr::CLIENT_FINGERPRINT, fingerprint);
            event.actor.ip = None;
            event
        };
        let events: Vec<Event> = (0..5)
            .map(|index| with_fingerprint(index, "FP-1"))
            .collect();
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].entities,
            [EntityRef::new(EntityKind::Other, "client_fingerprint:fp-1")]
        );
        assert_eq!(found[0].attributes["client"], json!("with no address"));
        assert_eq!(found[0].attributes["client_fingerprint"], json!("fp-1"));
        // An event with no address and no fingerprint has no client.
        let detector = self::detector();
        let mut events = missing(0, 0, 10);
        for event in &mut events {
            event.actor.ip = None;
        }
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn a_principal_and_a_fingerprint_are_entities_of_the_detection() {
        let detector = detector();
        let mut events = missing(0, 0, 5);
        for event in &mut events {
            event.actor = Actor::new(EntityKind::User, "user-1").with_ip(CLIENT.parse().unwrap());
            event
                .attributes
                .insert(attr::CLIENT_FINGERPRINT.to_owned(), json!("fp-9"));
        }
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].entities,
            [
                EntityRef::new(EntityKind::IpAddress, CLIENT),
                EntityRef::new(EntityKind::Other, "client_fingerprint:fp-9"),
                EntityRef::new(EntityKind::User, "user-1"),
            ]
        );
    }

    #[test]
    fn other_actions_and_events_with_no_path_are_ignored() {
        let detector = detector();
        let mut events = missing(0, 0, 10);
        for event in &mut events {
            event.action = action::NETWORK_CONNECT.to_owned();
        }
        assert_eq!(feed(&detector, &events).len(), 0);
        let mut events = missing(0, 0, 10);
        for event in &mut events {
            event.attributes.remove(attr::HTTP_PATH);
        }
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn an_event_that_arrives_late_is_counted_in_the_window() {
        let detector = detector();
        let events = missing(0, 0, 5);
        let order = [&events[4], &events[0], &events[1], &events[2], &events[3]];
        let found: Vec<Detection> = order
            .iter()
            .filter_map(|event| detector.evaluate(event))
            .collect();
        assert_eq!(found.len(), 1);
        // An event that is older than the window is not counted.
        let detector = self::detector();
        let mut events = missing(0, 20_000, 4);
        events.push(request(99, 0, "/very/old", 404));
        assert_eq!(feed(&detector, &events).len(), 0);
    }

    #[test]
    fn events_at_the_ends_of_the_time_range_do_not_panic() {
        let detector = detector();
        let mut events = missing(0, 0, 5);
        events[0].time = DateTime::<Utc>::MIN_UTC;
        for event in &mut events[1..] {
            event.time = DateTime::<Utc>::MAX_UTC;
        }
        assert_eq!(feed(&detector, &events).len(), 0);
        let mut decoy = request(9, 0, "/.env", 404);
        decoy.time = DateTime::<Utc>::MAX_UTC;
        assert!(detector.evaluate(&decoy).is_some());
    }

    #[test]
    fn the_state_is_limited() {
        let detector = EndpointProbe::new(EndpointProbeConfig {
            max_tracked_clients: 8,
            ..config()
        })
        .unwrap();
        for index in 0..1_000_u32 {
            let event = request_from(
                index,
                i64::from(index),
                &format!("203.0.{}.{}", index / 250, index % 250),
                "/missing",
                404,
            );
            assert_eq!(detector.evaluate(&event), None);
            assert!(lock(&detector.state).len() <= 8);
        }
        // One client keeps at most one entry for each path below the threshold.
        let detector = self::detector();
        for index in 0..1_000_u32 {
            let _ = detector.evaluate(&request(
                index,
                i64::from(index) * 3_000,
                &format!("/old/{index}"),
                404,
            ));
        }
        let state = lock(&detector.state);
        assert!(state.values().all(|client| client.missing.len() < 5));
    }

    #[test]
    fn text_from_the_event_is_cleaned_and_limited_in_the_detection() {
        let detector = detector();
        let mut events = missing(0, 0, 5);
        let long = format!("/\u{7}evil\n{}", "a".repeat(1_000));
        events[0]
            .attributes
            .insert(attr::HTTP_PATH.to_owned(), json!(long));
        events[4].actor.user_agent = Some(format!("agent\r\n{}", "b".repeat(1_000)));
        let found = feed(&detector, &events);
        assert_eq!(found.len(), 1);
        let sample = found[0].attributes["sample_paths"][0].as_str().unwrap();
        assert_eq!(sample.chars().count(), 160);
        assert!(sample.chars().all(|character| !character.is_control()));
        let user_agent = found[0].attributes["user_agent"].as_str().unwrap();
        assert_eq!(user_agent.chars().count(), 160);
        assert!(user_agent.chars().all(|character| !character.is_control()));
    }

    #[test]
    fn a_detector_that_is_not_enabled_gives_no_detection() {
        let detector = EndpointProbe::new(EndpointProbeConfig {
            enabled: false,
            ..config()
        })
        .unwrap();
        assert_eq!(feed(&detector, &missing(0, 0, 50)).len(), 0);
        assert_eq!(detector.evaluate(&request(99, 0, "/.env", 404)), None);
    }

    #[test]
    fn settings_that_are_not_valid_are_errors() {
        let base = EndpointProbeConfig::default;
        let cases = [
            (
                EndpointProbeConfig {
                    window_seconds: 0,
                    ..base()
                },
                "endpoint_probe.window_seconds must be 1 or more, but it is 0".to_owned(),
            ),
            (
                EndpointProbeConfig {
                    distinct_path_threshold: 1,
                    ..base()
                },
                "endpoint_probe.distinct_path_threshold must be 2 or more, but it is 1".to_owned(),
            ),
            (
                EndpointProbeConfig {
                    distinct_path_threshold: 1_001,
                    ..base()
                },
                "endpoint_probe.distinct_path_threshold must be 1000 or less, but it is 1001"
                    .to_owned(),
            ),
            (
                EndpointProbeConfig {
                    missing_statuses: vec![404, 99],
                    ..base()
                },
                "endpoint_probe.missing_statuses must hold status codes from 100 to 599, but \
                 it holds 99"
                    .to_owned(),
            ),
            (
                EndpointProbeConfig {
                    decoy_paths: vec!["admin".to_owned()],
                    ..base()
                },
                "endpoint_probe.decoy_paths: the path \"admin\" must start with \"/\" and can \
                 have one \"*\", at the end"
                    .to_owned(),
            ),
            (
                EndpointProbeConfig {
                    decoy_paths: vec!["/a*/b*".to_owned()],
                    ..base()
                },
                "endpoint_probe.decoy_paths: the path \"/a*/b*\" must start with \"/\" and can \
                 have one \"*\", at the end"
                    .to_owned(),
            ),
            (
                EndpointProbeConfig {
                    decoy_paths: vec!["/*".to_owned()],
                    ..base()
                },
                "endpoint_probe.decoy_paths: the path \"/*\" matches all paths".to_owned(),
            ),
            (
                EndpointProbeConfig {
                    max_tracked_clients: 0,
                    ..base()
                },
                "endpoint_probe.max_tracked_clients must be 1 or more, but it is 0".to_owned(),
            ),
            (
                EndpointProbeConfig {
                    cooldown_seconds: u64::MAX,
                    ..base()
                },
                format!("endpoint_probe.cooldown_seconds is too large: {}", u64::MAX),
            ),
        ];
        for (config, expected) in cases {
            let error = EndpointProbe::new(config).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!("detector configuration: {expected}")
            );
        }
    }

    #[test]
    fn the_default_settings_have_no_decoy_path() {
        let detector = EndpointProbe::new(EndpointProbeConfig::default()).unwrap();
        assert_eq!(detector.evaluate(&request(1, 0, "/.env", 404)), None);
        // The default threshold is 20 paths in 60 seconds.
        let found = feed(&detector, &missing(10, 0, 50));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].attributes["distinct_paths"], json!(20));
    }

    #[tokio::test]
    async fn the_detector_contract_returns_the_detection() {
        let detector = detector();
        assert_eq!(detector.id(), ENDPOINT_PROBE_RULE_ID);
        assert_eq!(detector.tier(), DetectionTier::Deterministic);
        let mut found = Vec::new();
        for event in &missing(0, 0, 10) {
            found.extend(detector.inspect(event).await.unwrap());
        }
        assert_eq!(found.len(), 1);
    }
}
