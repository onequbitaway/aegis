//! Indicators from detections and from decoy events.
//!
//! [`IndicatorSet::collect`] finds the values that other defenders can use to find the
//! same activity: addresses, domains, and user agents. A value becomes an indicator only
//! if evidence links it to an attack:
//!
//! - a detection with the verdict `malicious` names it, or cites an event that shows it;
//! - or a decoy event shows it. No approved client uses a decoy.
//!
//! A value that only normal activity shows never becomes an indicator. The export also
//! never gives an address or a domain of the operator. [`IndicatorSet::skipped`] tells
//! the operator what the export left out, and why.
//!
//! # Which side of an event is the remote side
//!
//! An event has the address of the actor, and it can have a destination. For activity
//! that comes in, the actor is the remote client and the destination is a system of the
//! operator. For a connection that goes out, the actor is a system of the operator. The
//! collector uses this rule:
//!
//! - If the actor has a public address, the actor is the remote side. The collector
//!   takes the address and the user agent of the actor. It ignores the destination.
//! - If the actor has no address, or an address that is private, reserved, or in an
//!   operator network, the destination is the remote side. The collector takes the
//!   destination address and the destination domain. It ignores the user agent.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use aegis_contracts::common::{DetectionId, EntityKind, EventId};
use aegis_contracts::detection::{Detection, Verdict};
use aegis_contracts::event::{Event, action, attr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::address::{AddressClass, AddressPolicy, canonical_address};
use crate::attack::{Technique, TechniqueSet};
use crate::error::ShareError;
use crate::secrets::scrub_secrets;
use crate::text::{MAX_TEXT_CHARS, MAX_USER_AGENT_CHARS, clean, is_unsafe_char, serialize_time};

/// The smallest length of a user agent indicator. A shorter text matches too many clients.
pub const MIN_USER_AGENT_CHARS: usize = 4;

/// The longest DNS name.
const MAX_DOMAIN_LENGTH: usize = 253;

/// The longest label of a DNS name.
const MAX_LABEL_LENGTH: usize = 63;

/// Domain suffixes for private use, for tests, and for infrastructure.
const RESERVED_SUFFIXES: &[&str] = &[
    "arpa",
    "corp",
    "home",
    "internal",
    "intranet",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "private",
    "test",
];

/// Domain suffixes that the IETF keeps for documentation.
const DOCUMENTATION_SUFFIXES: &[&str] = &["example", "example.com", "example.net", "example.org"];

/// The type of an indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// An IPv4 address.
    Ipv4,
    /// An IPv6 address.
    Ipv6,
    /// A DNS domain.
    Domain,
    /// The user agent of a client.
    UserAgent,
}

impl IndicatorKind {
    /// Returns the name of the type, as the CSV export writes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Domain => "domain",
            Self::UserAgent => "user_agent",
        }
    }
}

/// How strong the evidence for an indicator is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorBasis {
    /// A contact with a decoy, or a detection with the verdict `suspicious`.
    AnomalousActivity,
    /// A detection with the verdict `malicious`, or the use of a decoy credential.
    MaliciousActivity,
}

impl IndicatorBasis {
    /// Returns the value of the STIX vocabulary `indicator-type-ov` for this basis.
    #[must_use]
    pub fn stix_type(self) -> &'static str {
        match self {
            Self::AnomalousActivity => "anomalous-activity",
            Self::MaliciousActivity => "malicious-activity",
        }
    }
}

/// One indicator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Indicator {
    /// The type of the indicator.
    pub kind: IndicatorKind,
    /// The value: an address, a domain in lower case, or a user agent.
    pub value: String,
    /// How strong the evidence is.
    pub basis: IndicatorBasis,
    /// The time of the first evidence.
    #[serde(serialize_with = "serialize_time")]
    pub first_seen: DateTime<Utc>,
    /// The time of the last evidence.
    #[serde(serialize_with = "serialize_time")]
    pub last_seen: DateTime<Utc>,
    /// The number of evidence events that show the value.
    pub events: usize,
    /// The number of detections that name the value or cite an event that shows it.
    pub detections: usize,
    /// The ATT&CK techniques of those detections.
    pub techniques: Vec<Technique>,
}

/// Why the export left a value out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The address is in a network of the operator.
    OperatorAddress,
    /// The address is private.
    PrivateAddress,
    /// The address is a special-purpose address, for example a loopback address.
    ReservedAddress,
    /// The address is in a documentation range, and the options do not permit that.
    DocumentationAddress,
    /// A detection names an address entity that is not an IP address.
    NotAnAddress,
    /// The domain is a domain of the operator.
    OperatorDomain,
    /// The domain is for private use, for tests, or for infrastructure.
    ReservedDomain,
    /// The domain is a documentation domain, and the options do not permit that.
    DocumentationDomain,
    /// The text is not a DNS name in ASCII with two or more labels.
    InvalidDomain,
    /// A client that has no link to the attack shows the same value.
    SeenInNormalActivity,
    /// No client that shows the user agent has an address that the export can give.
    NoShareableClient,
    /// The user agent is shorter than [`MIN_USER_AGENT_CHARS`].
    TooShort,
    /// The user agent is longer than a document keeps.
    TooLong,
    /// The user agent has a control character or an invisible character.
    UnsafeCharacters,
    /// The user agent has a part that looks like a secret.
    HoldsSecret,
}

/// A value that the export left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedValue {
    /// The type that the value would have. `None` if the value has no valid type.
    pub kind: Option<IndicatorKind>,
    /// The value, with unsafe characters replaced and a limited length. Do not send it.
    pub value: String,
    /// Why the export left the value out.
    pub reason: SkipReason,
}

/// The options of [`IndicatorSet::collect`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndicatorOptions {
    /// Which addresses the export can give. With
    /// [`permit_documentation_ranges`](AddressPolicy::permit_documentation_ranges), the
    /// export also gives documentation domains. Use that only for tests and
    /// demonstrations.
    pub addresses: AddressPolicy,
    /// The domains of the operator. The export never gives them or their subdomains.
    pub operator_domains: Vec<String>,
    /// With `true`, a detection with the verdict `suspicious` also gives indicators.
    /// They get the basis [`IndicatorBasis::AnomalousActivity`].
    pub include_suspicious: bool,
}

impl IndicatorOptions {
    /// Makes the default options: no operator data, and only `malicious` detections.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the address policy.
    #[must_use]
    pub fn with_addresses(mut self, addresses: AddressPolicy) -> Self {
        self.addresses = addresses;
        self
    }

    /// Adds a domain of the operator.
    #[must_use]
    pub fn with_operator_domain(mut self, domain: impl Into<String>) -> Self {
        self.operator_domains.push(domain.into());
        self
    }
}

/// The indicators of a set of detections and events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndicatorSet {
    /// The indicators: addresses in order, then domains, then user agents.
    pub indicators: Vec<Indicator>,
    /// The values that the export left out. This list is for the operator. Do not send it.
    pub skipped: Vec<SkippedValue>,
}

/// Returns a DNS name in its usual form, or `None` if `text` is not a DNS name.
///
/// The usual form is lower case with no final full stop. The name must be ASCII and
/// must have two or more labels. An internationalized name must be in its ASCII form.
pub(crate) fn normal_domain(text: &str) -> Option<String> {
    let name = text.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > MAX_DOMAIN_LENGTH || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let valid = |label: &&str| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LENGTH
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    let numeric_top = labels
        .last()
        .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()));
    (labels.len() >= 2 && labels.iter().all(valid) && !numeric_top).then_some(name)
}

/// Returns `true` if `name` is `suffix` or a subdomain of it.
fn in_domain(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|head| head.ends_with('.'))
}

/// The evidence for one value.
#[derive(Default)]
struct Candidate {
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
    events: HashSet<EventId>,
    detections: HashSet<DetectionId>,
    malicious: bool,
    techniques: TechniqueSet,
    /// For a user agent: the addresses of the clients that show it.
    clients: BTreeSet<IpAddr>,
}

impl Candidate {
    fn touch_time(&mut self, time: DateTime<Utc>) {
        self.first = Some(self.first.map_or(time, |first| first.min(time)));
        self.last = Some(self.last.map_or(time, |last| last.max(time)));
    }

    fn add_detection(&mut self, detection: &Detection) {
        self.detections.insert(detection.id);
        self.malicious |= detection.verdict == Verdict::Malicious;
        for technique in &detection.attack {
            // An indicator carries no technique name, so the name needs no masking.
            self.techniques
                .add(technique, detection.tier, |name| name.to_owned());
        }
    }

    /// Adds a detection that names the value as an entity.
    fn named_by(&mut self, detection: &Detection) {
        self.touch_time(detection.time);
        self.add_detection(detection);
    }

    /// Adds an evidence event that shows the value.
    fn shown_by(&mut self, event: &Event, detections: &[&Detection]) {
        self.touch_time(event.time);
        self.events.insert(event.id);
        self.malicious |= event.action == action::HONEYTOKEN_TRIP;
        for detection in detections {
            self.add_detection(detection);
        }
    }

    fn into_indicator(self, kind: IndicatorKind, value: String) -> Option<Indicator> {
        let (first_seen, last_seen) = (self.first?, self.last?);
        Some(Indicator {
            kind,
            value,
            basis: if self.malicious {
                IndicatorBasis::MaliciousActivity
            } else {
                IndicatorBasis::AnomalousActivity
            },
            first_seen,
            last_seen,
            events: self.events.len(),
            detections: self.detections.len(),
            techniques: self
                .techniques
                .into_vec()
                .into_iter()
                .map(|technique| Technique {
                    name: None,
                    ..technique
                })
                .collect(),
        })
    }
}

fn is_decoy_event(event: &Event) -> bool {
    matches!(
        event.action.as_str(),
        action::DECOY_CONTACT | action::DECOY_CANARY_HIT | action::HONEYTOKEN_TRIP
    )
}

fn qualifies(verdict: Verdict, include_suspicious: bool) -> bool {
    match verdict {
        Verdict::Malicious => true,
        Verdict::Suspicious => include_suspicious,
        Verdict::Benign => false,
    }
}

/// The two sides of an event.
struct Sides {
    /// The address of the actor, if the actor is the remote side.
    remote_actor: Option<IpAddr>,
    /// The destination address, if the destination is the remote side.
    remote_destination: Option<IpAddr>,
    /// `true` if the actor is a system of the operator, or has no address.
    actor_is_local: bool,
}

fn sides(event: &Event, policy: &AddressPolicy) -> Sides {
    let actor = event.actor.ip.map(canonical_address);
    let actor_is_local = actor.is_none_or(|address| {
        matches!(
            policy.classify(address),
            AddressClass::Operator | AddressClass::Private | AddressClass::Reserved
        )
    });
    let destination = event
        .attribute_str(attr::DESTINATION_IP)
        .and_then(|text| text.trim().parse::<IpAddr>().ok())
        .map(canonical_address);
    Sides {
        remote_actor: actor.filter(|_| !actor_is_local),
        remote_destination: destination.filter(|_| actor_is_local),
        actor_is_local,
    }
}

/// Returns the domain that an event names as its destination.
fn destination_domain(event: &Event) -> Option<&str> {
    event.attribute_str(attr::DESTINATION_DOMAIN).or_else(|| {
        event
            .target
            .as_ref()
            .filter(|target| target.kind == EntityKind::Domain)
            .map(|target| target.id.as_str())
    })
}

fn address_kind(address: IpAddr) -> IndicatorKind {
    match address {
        IpAddr::V4(_) => IndicatorKind::Ipv4,
        IpAddr::V6(_) => IndicatorKind::Ipv6,
    }
}

fn skipped(kind: Option<IndicatorKind>, value: &str, reason: SkipReason) -> SkippedValue {
    SkippedValue {
        kind,
        value: clean(value, MAX_USER_AGENT_CHARS),
        reason,
    }
}

impl IndicatorSet {
    /// Collects the indicators of `detections` and of the decoy events in `events`.
    ///
    /// `events` can hold normal activity. The collector uses it to find values that
    /// clients with no link to the attack also show. It leaves such a user agent or
    /// domain out.
    ///
    /// The result is the same for the same input. It does not depend on the order of the
    /// detections or of the events.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::InvalidOption`] if an operator domain is not a DNS name. A
    /// wrong entry would turn off the protection of that domain.
    pub fn collect(
        detections: &[Detection],
        events: &[Event],
        options: &IndicatorOptions,
    ) -> Result<Self, ShareError> {
        let mut operator_domains: Vec<String> = Vec::with_capacity(options.operator_domains.len());
        for domain in &options.operator_domains {
            let normal = normal_domain(domain).ok_or_else(|| {
                ShareError::option(
                    "operator_domains",
                    "an entry is not a DNS name with two or more labels",
                )
            })?;
            operator_domains.push(normal);
        }
        let policy = &options.addresses;

        let mut by_id: HashMap<EventId, &Event> = HashMap::with_capacity(events.len());
        for event in events {
            by_id.entry(event.id).or_insert(event);
        }
        let mut used: Vec<&Detection> = detections
            .iter()
            .filter(|detection| qualifies(detection.verdict, options.include_suspicious))
            .collect();
        used.sort_by_key(|detection| (detection.time, detection.id));
        used.dedup_by_key(|detection| detection.id);

        let mut addresses: BTreeMap<IpAddr, Candidate> = BTreeMap::new();
        let mut domains: BTreeMap<String, Candidate> = BTreeMap::new();
        let mut user_agents: BTreeMap<String, Candidate> = BTreeMap::new();
        let mut left_out: Vec<SkippedValue> = Vec::new();
        let mut citing: HashMap<EventId, Vec<&Detection>> = HashMap::new();

        // The values that a detection names as entities.
        for detection in &used {
            for entity in &detection.entities {
                match entity.kind {
                    EntityKind::IpAddress => match entity.id.trim().parse::<IpAddr>() {
                        Ok(address) => addresses
                            .entry(canonical_address(address))
                            .or_default()
                            .named_by(detection),
                        Err(_) => {
                            left_out.push(skipped(None, &entity.id, SkipReason::NotAnAddress))
                        }
                    },
                    EntityKind::Domain => match normal_domain(&entity.id) {
                        Some(name) => domains.entry(name).or_default().named_by(detection),
                        None => left_out.push(skipped(
                            Some(IndicatorKind::Domain),
                            &entity.id,
                            SkipReason::InvalidDomain,
                        )),
                    },
                    _ => {}
                }
            }
            for id in &detection.event_ids {
                if by_id.contains_key(id) {
                    citing.entry(*id).or_default().push(detection);
                }
            }
        }

        // The evidence events: each event that a used detection cites, and each decoy event.
        let mut evidence: Vec<&Event> = by_id
            .values()
            .copied()
            .filter(|event| citing.contains_key(&event.id) || is_decoy_event(event))
            .collect();
        evidence.sort_by_key(|event| (event.time, event.id));
        let evidence_ids: HashSet<EventId> = evidence.iter().map(|event| event.id).collect();
        let mut linked_actors: HashSet<(EntityKind, &str)> = HashSet::new();
        let no_detections: Vec<&Detection> = Vec::new();
        for event in &evidence {
            let cited_by = citing.get(&event.id).unwrap_or(&no_detections);
            let sides = sides(event, policy);
            linked_actors.insert((event.actor.kind, event.actor.id.as_str()));
            for address in sides.remote_actor.iter().chain(&sides.remote_destination) {
                addresses
                    .entry(*address)
                    .or_default()
                    .shown_by(event, cited_by);
            }
            if let (Some(client), Some(user_agent)) =
                (sides.remote_actor, event.actor.user_agent.as_deref())
            {
                let candidate = user_agents.entry(user_agent.trim().to_owned()).or_default();
                candidate.shown_by(event, cited_by);
                candidate.clients.insert(client);
            }
            if sides.actor_is_local
                && let Some(text) = destination_domain(event)
            {
                match normal_domain(text) {
                    Some(name) => domains.entry(name).or_default().shown_by(event, cited_by),
                    None => left_out.push(skipped(
                        Some(IndicatorKind::Domain),
                        text,
                        SkipReason::InvalidDomain,
                    )),
                }
            }
        }

        // The values that a client with no link to the attack also shows.
        let mut usual_user_agents: HashSet<String> = HashSet::new();
        let mut usual_domains: HashSet<String> = HashSet::new();
        for event in by_id
            .values()
            .filter(|event| !evidence_ids.contains(&event.id))
        {
            let address = event.actor.ip.map(canonical_address);
            let linked_address = address.is_some_and(|address| addresses.contains_key(&address));
            if !linked_address && let Some(user_agent) = event.actor.user_agent.as_deref() {
                usual_user_agents.insert(user_agent.trim().to_ascii_lowercase());
            }
            let linked_actor = linked_actors.contains(&(event.actor.kind, event.actor.id.as_str()));
            if !linked_address
                && !linked_actor
                && let Some(name) = destination_domain(event).and_then(normal_domain)
            {
                usual_domains.insert(name);
            }
        }

        let mut indicators: Vec<Indicator> = Vec::new();
        for (address, candidate) in addresses {
            let kind = address_kind(address);
            let reason = match policy.classify(address) {
                AddressClass::Global => None,
                AddressClass::Documentation if policy.permit_documentation_ranges => None,
                AddressClass::Documentation => Some(SkipReason::DocumentationAddress),
                AddressClass::Operator => Some(SkipReason::OperatorAddress),
                AddressClass::Private => Some(SkipReason::PrivateAddress),
                AddressClass::Reserved => Some(SkipReason::ReservedAddress),
            };
            match reason {
                Some(reason) => left_out.push(skipped(Some(kind), &address.to_string(), reason)),
                None => indicators.extend(candidate.into_indicator(kind, address.to_string())),
            }
        }
        for (name, candidate) in domains {
            let reason = if operator_domains
                .iter()
                .any(|domain| in_domain(&name, domain))
            {
                Some(SkipReason::OperatorDomain)
            } else if RESERVED_SUFFIXES
                .iter()
                .any(|suffix| in_domain(&name, suffix))
            {
                Some(SkipReason::ReservedDomain)
            } else if !policy.permit_documentation_ranges
                && DOCUMENTATION_SUFFIXES
                    .iter()
                    .any(|suffix| in_domain(&name, suffix))
            {
                Some(SkipReason::DocumentationDomain)
            } else if usual_domains.contains(&name) {
                Some(SkipReason::SeenInNormalActivity)
            } else {
                None
            };
            match reason {
                Some(reason) => left_out.push(skipped(Some(IndicatorKind::Domain), &name, reason)),
                None => indicators.extend(candidate.into_indicator(IndicatorKind::Domain, name)),
            }
        }
        for (user_agent, candidate) in user_agents {
            let length = user_agent.chars().count();
            let reason = if length < MIN_USER_AGENT_CHARS {
                Some(SkipReason::TooShort)
            } else if length > MAX_TEXT_CHARS {
                Some(SkipReason::TooLong)
            } else if user_agent.chars().any(is_unsafe_char) {
                Some(SkipReason::UnsafeCharacters)
            } else if scrub_secrets(&user_agent) != user_agent {
                Some(SkipReason::HoldsSecret)
            } else if !candidate
                .clients
                .iter()
                .any(|client| policy.permits(*client))
            {
                Some(SkipReason::NoShareableClient)
            } else if usual_user_agents.contains(&user_agent.to_ascii_lowercase()) {
                Some(SkipReason::SeenInNormalActivity)
            } else {
                None
            };
            match reason {
                // A user agent can hold a secret. The note for the operator must not.
                Some(SkipReason::HoldsSecret) => left_out.push(skipped(
                    Some(IndicatorKind::UserAgent),
                    &scrub_secrets(&user_agent),
                    SkipReason::HoldsSecret,
                )),
                Some(reason) => {
                    left_out.push(skipped(Some(IndicatorKind::UserAgent), &user_agent, reason));
                }
                None => indicators
                    .extend(candidate.into_indicator(IndicatorKind::UserAgent, user_agent)),
            }
        }
        left_out.sort_by(|left, right| {
            (left.kind, &left.value, left.reason).cmp(&(right.kind, &right.value, right.reason))
        });
        left_out.dedup();
        Ok(Self {
            indicators,
            skipped: left_out,
        })
    }

    /// Returns the indicators of one type, in order.
    pub fn of_kind(&self, kind: IndicatorKind) -> impl Iterator<Item = &Indicator> {
        self.indicators
            .iter()
            .filter(move |indicator| indicator.kind == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_gets_its_usual_form() {
        assert_eq!(
            normal_domain("Evil.Example.ORG."),
            Some("evil.example.org".to_owned())
        );
        assert_eq!(
            normal_domain(" c2.bad-host.net "),
            Some("c2.bad-host.net".to_owned())
        );
        assert_eq!(
            normal_domain("_dmarc.bad.net"),
            Some("_dmarc.bad.net".to_owned())
        );
        assert_eq!(
            normal_domain("xn--bcher-kva.example"),
            Some("xn--bcher-kva.example".to_owned())
        );
    }

    #[test]
    fn text_that_is_not_a_dns_name_is_not_a_domain() {
        let long_label = format!("{}.net", "a".repeat(64));
        let long_name = format!("{}.net", "a.".repeat(130));
        for bad in [
            "",
            ".",
            "localhost",
            "no dots",
            "bad..net",
            "-bad.net",
            "bad-.net",
            "bad.net/path",
            "bad.net:443",
            "user@bad.net",
            "bücher.example",
            "203.0.113.50",
            "2001:db8::1",
            "bad.123",
            "bad\n.net",
            "<script>.net",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert_eq!(normal_domain(bad), None, "{bad:?}");
        }
        // A final line feed is white space. The name stays valid without it.
        assert_eq!(normal_domain("bad.net \t"), Some("bad.net".to_owned()));
    }

    #[test]
    fn a_suffix_matches_only_at_a_label_border() {
        assert!(in_domain("contoso.example", "contoso.example"));
        assert!(in_domain("login.contoso.example", "contoso.example"));
        assert!(!in_domain("notcontoso.example", "contoso.example"));
        assert!(!in_domain("contoso.example.net", "contoso.example"));
        assert!(in_domain("printer.local", "local"));
        assert!(!in_domain("notlocal", "local"));
    }

    #[test]
    fn the_type_names_and_the_stix_types_are_fixed() {
        assert_eq!(IndicatorKind::Ipv4.name(), "ipv4");
        assert_eq!(IndicatorKind::Ipv6.name(), "ipv6");
        assert_eq!(IndicatorKind::Domain.name(), "domain");
        assert_eq!(IndicatorKind::UserAgent.name(), "user_agent");
        assert_eq!(
            IndicatorBasis::MaliciousActivity.stix_type(),
            "malicious-activity"
        );
        assert_eq!(
            IndicatorBasis::AnomalousActivity.stix_type(),
            "anomalous-activity"
        );
    }
}
