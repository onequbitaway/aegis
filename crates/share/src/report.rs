//! The abuse report package of one incident.
//!
//! [`AbuseReport::build`] makes one report for each attacker address of an incident. If
//! the caller supplies a [`NetworkMap`], it also makes one report for each hosting
//! network. Each report is a complete document for one receiver: it holds only the
//! records of its own addresses.
//!
//! # What a report says
//!
//! All text of a report comes from templates in this module and from checked fields of
//! the log records. The builder copies no title, summary, or timeline of the incident.
//! It copies no title and no description of a detection. A model or an analyst can
//! write those texts, and they can name a person or a group. A report thus states only
//! what the log records show.
//!
//! # Claims and evidence
//!
//! A report is a list of claims. Each claim names the evidence items that show it. The
//! builder drops a claim that has no evidence item, and it writes a [`BuildNote`] for the
//! operator.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use aegis_contracts::audit::{AuditKind, AuditRecord};
use aegis_contracts::common::{AuditId, DetectionId, EntityKind, EventId, EvidenceKind, TimeRange};
use aegis_contracts::detection::{Detection, Verdict};
use aegis_contracts::event::{Event, Outcome, action, attr};
use aegis_contracts::incident::{Incident, IncidentStatus};
use chrono::{DateTime, TimeDelta, Utc};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::address::{AddressClass, AddressPolicy, canonical_address};
use crate::attack::{Technique, TechniqueSet};
use crate::error::ShareError;
use crate::evidence::{
    EVIDENCE_FILE_NAME, EvidenceItem, EvidenceItemKind, EvidenceManifest, evidence_jsonl, item_id,
};
use crate::minimize::{AllowList, Minimizer, Redactor, shown_action};
use crate::text::{
    MAX_TOKEN_CHARS, clean, json_pretty, md_code, md_text, serialize_time, time_text, token,
};

/// The format name of the JSON form of a report.
pub const REPORT_FORMAT: &str = "aegis.abuse-report/1";

/// The statement that each report carries about its limits.
pub const NOTICE: &str = "This report gives log data of the reporter. It does not identify a \
                          person or a group.";

/// The default time before the first detection and after the last detection in which a
/// record of an attacker address goes into the report.
pub const DEFAULT_ACTIVITY_MARGIN_SECONDS: i64 = 3600;

/// The default largest number of evidence items for one address.
pub const DEFAULT_MAX_EVIDENCE_ITEMS: usize = 1000;

/// The default number of log lines that a claim shows as an excerpt.
pub const DEFAULT_EXCERPT_LINES: usize = 3;

/// The organization that sends a report.
///
/// The builder puts no reporter in a report unless the caller gives one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reporter {
    /// The name that the receiver sees.
    pub name: String,
    /// How the receiver can reply, for example a mailbox.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
}

/// The network that hosts an attacker address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct HostingNetwork {
    /// The name of the network or of its operator, for example `AS64500 Example Hosting`.
    pub name: String,
    /// The abuse contact of the network, if the caller knows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abuse_contact: Option<String>,
}

impl HostingNetwork {
    /// Makes a network with no abuse contact.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            abuse_contact: None,
        }
    }

    /// Sets the abuse contact.
    #[must_use]
    pub fn with_abuse_contact(mut self, contact: impl Into<String>) -> Self {
        self.abuse_contact = Some(contact.into());
        self
    }
}

/// A map from addresses to the networks that host them.
///
/// This crate makes no network request. The caller finds the network of each address,
/// for example in a registry, and gives the result here.
///
/// ```
/// use aegis_share::{HostingNetwork, NetworkMap};
///
/// let hosting = HostingNetwork::new("AS64500 Example Hosting");
/// let map = NetworkMap::new()
///     .with_prefix("203.0.113.0/24".parse()?, hosting.clone())
///     .with_address("192.0.2.77".parse()?, HostingNetwork::new("AS64501 Example Cloud"));
/// assert_eq!(map.lookup("203.0.113.50".parse()?), Some(&hosting));
/// assert_eq!(map.lookup("198.51.100.1".parse()?), None);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkMap {
    addresses: BTreeMap<IpAddr, HostingNetwork>,
    prefixes: Vec<(IpNet, HostingNetwork)>,
}

impl NetworkMap {
    /// Makes an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives the network of one address.
    #[must_use]
    pub fn with_address(mut self, address: IpAddr, network: HostingNetwork) -> Self {
        self.addresses.insert(canonical_address(address), network);
        self
    }

    /// Gives the network of all addresses in `prefix`.
    #[must_use]
    pub fn with_prefix(mut self, prefix: IpNet, network: HostingNetwork) -> Self {
        self.prefixes.push((prefix, network));
        self
    }

    /// Returns `true` if the map has no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty() && self.prefixes.is_empty()
    }

    /// Returns the network of `address`.
    ///
    /// An entry for the address wins. If there is none, the longest prefix wins.
    #[must_use]
    pub fn lookup(&self, address: IpAddr) -> Option<&HostingNetwork> {
        let address = canonical_address(address);
        if let Some(network) = self.addresses.get(&address) {
            return Some(network);
        }
        self.prefixes
            .iter()
            .filter(|(prefix, _)| prefix.contains(&address))
            .max_by_key(|(prefix, _)| prefix.prefix_len())
            .map(|(_, network)| network)
    }
}

/// The options of [`AbuseReport::build`].
///
/// The defaults keep the least data. Each option that keeps more data is off.
#[derive(Debug, Clone, PartialEq)]
pub struct AbuseReportOptions {
    /// The time of the report. The builder does not read the clock, so that the same
    /// input gives the same package.
    pub generated_at: DateTime<Utc>,
    /// Which addresses a report can name.
    pub addresses: AddressPolicy,
    /// Which fields and attributes of an event stay in the evidence.
    pub allow: AllowList,
    /// The hosting networks of the addresses. With an empty map, the package has no
    /// network report.
    pub networks: NetworkMap,
    /// The organization that sends the report.
    pub reporter: Option<Reporter>,
    /// With `true`, a detection with the verdict `suspicious` also makes an address an
    /// attacker address. The default uses only `malicious` detections.
    pub include_suspicious: bool,
    /// With `true`, a report says that a service or a credential is a decoy. The default
    /// gives decoy activity a neutral name, because a receiver often sends the report to
    /// its customer.
    pub disclose_decoys: bool,
    /// The time before the first detection and after the last detection in which a
    /// record of an attacker address goes into the report.
    pub activity_margin: TimeDelta,
    /// The time range of the records. With a value, `activity_margin` has no effect.
    pub window: Option<TimeRange>,
    /// The largest number of evidence items for one address.
    pub max_evidence_items: usize,
    /// The number of log lines that a claim shows as an excerpt.
    pub excerpt_lines: usize,
}

impl AbuseReportOptions {
    /// Makes the default options for a report with the time `generated_at`.
    #[must_use]
    pub fn new(generated_at: DateTime<Utc>) -> Self {
        Self {
            generated_at,
            addresses: AddressPolicy::default(),
            allow: AllowList::default(),
            networks: NetworkMap::default(),
            reporter: None,
            include_suspicious: false,
            disclose_decoys: false,
            activity_margin: TimeDelta::seconds(DEFAULT_ACTIVITY_MARGIN_SECONDS),
            window: None,
            max_evidence_items: DEFAULT_MAX_EVIDENCE_ITEMS,
            excerpt_lines: DEFAULT_EXCERPT_LINES,
        }
    }

    /// Sets the address policy.
    #[must_use]
    pub fn with_addresses(mut self, addresses: AddressPolicy) -> Self {
        self.addresses = addresses;
        self
    }

    /// Sets the allow list.
    #[must_use]
    pub fn with_allow(mut self, allow: AllowList) -> Self {
        self.allow = allow;
        self
    }

    /// Sets the hosting networks.
    #[must_use]
    pub fn with_networks(mut self, networks: NetworkMap) -> Self {
        self.networks = networks;
        self
    }

    /// Sets the reporter.
    #[must_use]
    pub fn with_reporter(mut self, reporter: Reporter) -> Self {
        self.reporter = Some(reporter);
        self
    }

    fn validate(&self) -> Result<(), ShareError> {
        if self.max_evidence_items == 0 {
            return Err(ShareError::option(
                "max_evidence_items",
                "the value must be 1 or more",
            ));
        }
        if self.excerpt_lines == 0 {
            return Err(ShareError::option(
                "excerpt_lines",
                "the value must be 1 or more",
            ));
        }
        if self.activity_margin < TimeDelta::zero() {
            return Err(ShareError::option(
                "activity_margin",
                "the value must not be negative",
            ));
        }
        if let Some(window) = self.window
            && window.end <= window.start
        {
            return Err(ShareError::option(
                "window",
                "the end must be after the start",
            ));
        }
        Ok(())
    }
}

/// What a report is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReportSubject {
    /// One attacker address.
    Address {
        /// The address.
        address: IpAddr,
    },
    /// All attacker addresses in one hosting network.
    Network {
        /// The name of the network, as the caller gave it.
        name: String,
        /// The abuse contact of the network, as the caller gave it.
        #[serde(skip_serializing_if = "Option::is_none")]
        abuse_contact: Option<String>,
        /// The attacker addresses in the network, in order.
        addresses: Vec<IpAddr>,
    },
}

/// The type of a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// The log records show activity from the address.
    Activity,
    /// A detection rule of the reporter classified activity from the address.
    Detection,
}

/// One statement of a report, with the evidence that shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claim {
    /// The identifier of the claim in its report, for example `C1`.
    pub id: String,
    /// The type of the claim.
    pub kind: ClaimKind,
    /// The address that the claim is about.
    pub address: IpAddr,
    /// A short title.
    pub title: String,
    /// What occurred, in plain words. The text comes from a template.
    pub statement: String,
    /// The action name of the records, for an activity claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The time of the first record of the claim.
    #[serde(serialize_with = "serialize_time")]
    pub first_seen: DateTime<Utc>,
    /// The time of the last record of the claim.
    #[serde(serialize_with = "serialize_time")]
    pub last_seen: DateTime<Utc>,
    /// The number of log records that the claim describes.
    pub records: usize,
    /// The verdict of the detection, for a detection claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// The ATT&CK techniques, for a detection claim.
    pub techniques: Vec<Technique>,
    /// The identifiers of the evidence items. The list is never empty.
    pub evidence: Vec<String>,
    /// The first evidence items, as a short log excerpt.
    pub excerpt: Vec<String>,
}

/// A value that the records of an address show, with the number of records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedValue {
    /// The value, with masked data and unsafe characters replaced.
    pub value: String,
    /// The number of evidence items that show the value.
    pub records: usize,
}

/// A destination port that the records of an address show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObservedPort {
    /// The port number.
    pub port: u16,
    /// The number of evidence items that show the port.
    pub records: usize,
}

/// What the records show about one attacker address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressActivity {
    /// The address.
    pub address: IpAddr,
    /// The time of the first record from the address.
    #[serde(serialize_with = "serialize_time")]
    pub first_seen: DateTime<Utc>,
    /// The time of the last record from the address.
    #[serde(serialize_with = "serialize_time")]
    pub last_seen: DateTime<Utc>,
    /// The number of log records from the address in the time range of the report.
    pub records: usize,
    /// The number of those records that are evidence items of the report.
    pub records_in_evidence: usize,
    /// The destination ports, in order.
    pub ports: Vec<ObservedPort>,
    /// The user agents, in order.
    pub user_agents: Vec<ObservedValue>,
    /// The client fingerprints, in order. A fingerprint is a heuristic.
    pub client_fingerprints: Vec<ObservedValue>,
    /// The claims about the address.
    pub claims: Vec<Claim>,
}

/// One abuse report: a complete document for one receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbuseReport {
    /// The format name. The value is always [`REPORT_FORMAT`].
    pub format: String,
    /// The reference of the report. Use it in each reply.
    pub reference: String,
    /// What the report is about.
    pub subject: ReportSubject,
    /// The time of the report.
    #[serde(serialize_with = "serialize_time")]
    pub generated_at: DateTime<Utc>,
    /// The organization that sends the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reporter: Option<Reporter>,
    /// The time of the first record in the report.
    #[serde(serialize_with = "serialize_time")]
    pub first_seen: DateTime<Utc>,
    /// The time of the last record in the report.
    #[serde(serialize_with = "serialize_time")]
    pub last_seen: DateTime<Utc>,
    /// The activity of each address.
    pub addresses: Vec<AddressActivity>,
    /// The ATT&CK techniques of all detection claims.
    pub techniques: Vec<Technique>,
    /// The evidence items.
    pub evidence: Vec<EvidenceItem>,
    /// The hashes of the evidence items.
    pub manifest: EvidenceManifest,
    /// The statement about the limits of the report. The value is always [`NOTICE`].
    pub notice: String,
}

/// One file of a report, as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFile {
    /// The name of the file.
    pub name: &'static str,
    /// The contents of the file.
    pub content: String,
}

/// A fact about the build that the operator must know. A note is not a part of a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "note", rename_all = "snake_case")]
pub enum BuildNote {
    /// The policy does not permit a report about this address.
    AddressExcluded {
        /// The address.
        address: IpAddr,
        /// The class of the address.
        class: AddressClass,
    },
    /// A detection names an address entity that is not an IP address.
    EntityNotAnAddress {
        /// The detection.
        detection: DetectionId,
    },
    /// The builder did not use a detection, because of its verdict.
    DetectionNotUsed {
        /// The detection.
        detection: DetectionId,
        /// The verdict of the detection.
        verdict: Verdict,
    },
    /// A detection names the address, but the supplied events have no record from it.
    AddressWithoutRecords {
        /// The address.
        address: IpAddr,
    },
    /// The builder dropped a detection claim, because it has no evidence item.
    DetectionWithoutEvidence {
        /// The address of the claim.
        address: IpAddr,
        /// The detection.
        detection: DetectionId,
    },
    /// The builder dropped an activity claim, because the limit left it no evidence item.
    ActivityWithoutEvidence {
        /// The address of the claim.
        address: IpAddr,
        /// The number of records of the claim.
        records: usize,
    },
    /// The address has more records than the limit. The report holds a part of them.
    EvidenceLimited {
        /// The address.
        address: IpAddr,
        /// The number of records from the address.
        records: usize,
        /// The number of records in the report.
        included: usize,
    },
}

/// The reports of one incident, and the notes for the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbuseReportPackage {
    /// One report for each attacker address, in the order of the addresses. Then one
    /// report for each hosting network, in the order of the network names.
    pub reports: Vec<AbuseReport>,
    /// What the builder left out, and why. Do not send the notes.
    pub notes: Vec<BuildNote>,
}

/// The records of one attacker address.
struct Section<'a> {
    address: IpAddr,
    /// All records from the address in the time range, in time order.
    records: Vec<&'a Event>,
    /// The records that become evidence items.
    included: HashSet<EventId>,
    /// The detections that name the address or cite a record from it.
    detections: Vec<&'a Detection>,
}

/// The inputs that each report of a package shares.
struct Context<'a> {
    incident: &'a Incident,
    audit_records: Vec<&'a AuditRecord>,
    options: &'a AbuseReportOptions,
    redactor: &'a Redactor,
}

/// The words for one action: one item, and many items.
struct Phrase {
    one: &'static str,
    many: &'static str,
}

const fn phrase(one: &'static str, many: &'static str) -> Phrase {
    Phrase { one, many }
}

/// Returns the plain words for a shown action name.
fn action_phrase(name: &str) -> Phrase {
    match name {
        action::SIGN_IN => phrase("sign-in attempt", "sign-in attempts"),
        action::SIGN_OUT => phrase("sign-out", "sign-outs"),
        action::OAUTH_CONSENT_GRANT => phrase(
            "grant of consent to an application",
            "grants of consent to an application",
        ),
        action::APP_CREATE => phrase(
            "registration of an application",
            "registrations of an application",
        ),
        action::APP_CREDENTIAL_ADD => phrase(
            "addition of a credential to an application",
            "additions of a credential to an application",
        ),
        action::APP_CREDENTIAL_REMOVE => phrase(
            "removal of a credential from an application",
            "removals of a credential from an application",
        ),
        action::APP_PERMISSION_GRANT => phrase(
            "grant of an application permission",
            "grants of an application permission",
        ),
        action::SERVICE_PRINCIPAL_CREATE => phrase(
            "creation of a service principal",
            "creations of a service principal",
        ),
        action::SERVICE_PRINCIPAL_DISABLE => phrase(
            "change that disabled a service principal",
            "changes that disabled a service principal",
        ),
        action::ROLE_ASSIGN => phrase(
            "assignment of a directory role",
            "assignments of a directory role",
        ),
        action::ROLE_REMOVE => phrase(
            "removal of a directory role",
            "removals of a directory role",
        ),
        action::USER_CREATE => phrase("creation of a user account", "creations of a user account"),
        action::USER_UPDATE => phrase("change to a user account", "changes to a user account"),
        action::USER_PASSWORD_RESET => phrase("password reset", "password resets"),
        action::MFA_METHOD_CHANGE => phrase(
            "change to a multi-factor authentication method",
            "changes to a multi-factor authentication method",
        ),
        action::API_CALL => phrase("API call", "API calls"),
        action::SECRET_READ => phrase("read of a secret", "reads of a secret"),
        action::NETWORK_CONNECT => phrase("network connection", "network connections"),
        action::PROCESS_START => phrase("process start", "process starts"),
        action::HONEYTOKEN_TRIP => {
            phrase("use of a decoy credential", "uses of a decoy credential")
        }
        action::DECOY_CONTACT => {
            phrase("request to a decoy service", "requests to a decoy service")
        }
        action::DECOY_CANARY_HIT => phrase(
            "request to a canary address of a decoy service",
            "requests to a canary address of a decoy service",
        ),
        action::HTTP_REQUEST => phrase("HTTP request", "HTTP requests"),
        "service.contact" => phrase(
            "request to a service of the reporter",
            "requests to a service of the reporter",
        ),
        "secret.access" => phrase(
            "access to a protected secret",
            "accesses to a protected secret",
        ),
        _ => phrase(
            "log record with an action that has no plain name",
            "log records with an action that has no plain name",
        ),
    }
}

fn capitalized(text: &str) -> String {
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().chain(characters).collect(),
        None => String::new(),
    }
}

fn counted(number: usize, one: &str, many: &str) -> String {
    if number == 1 {
        format!("1 {one}")
    } else {
        format!("{number} {many}")
    }
}

/// Returns the sentence about the times of `number` records.
fn time_sentence(number: usize, first: DateTime<Utc>, last: DateTime<Utc>) -> String {
    if number == 1 || first == last {
        format!("The time was {}.", time_text(first))
    } else {
        format!(
            "The first was at {}. The last was at {}.",
            time_text(first),
            time_text(last)
        )
    }
}

fn activity_title(words: &Phrase, outcome: Outcome, number: usize) -> String {
    let noun = if number == 1 { words.one } else { words.many };
    let result = match outcome {
        Outcome::Success => "that succeeded",
        Outcome::Failure => "that failed",
        Outcome::Unknown => "with no recorded result",
    };
    capitalized(&format!("{noun} {result}"))
}

fn activity_statement(
    address: IpAddr,
    words: &Phrase,
    outcome: Outcome,
    records: &[&Event],
    in_evidence: usize,
) -> String {
    let number = records.len();
    let result = match (outcome, number) {
        (Outcome::Success, 1) => "It succeeded.".to_owned(),
        (Outcome::Failure, 1) => "It failed.".to_owned(),
        (Outcome::Unknown, 1) => "The record gives no result.".to_owned(),
        (Outcome::Success, _) => format!("All {number} succeeded."),
        (Outcome::Failure, _) => format!("All {number} failed."),
        (Outcome::Unknown, _) => "The records give no result.".to_owned(),
    };
    let first = records
        .first()
        .map_or(DateTime::UNIX_EPOCH, |event| event.time);
    let last = records.last().map_or(first, |event| event.time);
    // The accounts of the reporter that the records name. A decoy contact names none.
    let accounts: BTreeSet<(EntityKind, &str)> = records
        .iter()
        .filter(|event| {
            matches!(
                event.actor.kind,
                EntityKind::User | EntityKind::ServicePrincipal | EntityKind::Application
            )
        })
        .map(|event| (event.actor.kind, event.actor.id.as_str()))
        .collect();
    let mut text = format!(
        "The log records show {} from the address {address}. {result} {}",
        counted(number, words.one, words.many),
        time_sentence(number, first, last),
    );
    match accounts.len() {
        0 => {}
        1 => text.push_str(" The records name 1 account."),
        many => text.push_str(&format!(" The records name {many} different accounts.")),
    }
    if in_evidence < number {
        text.push_str(&format!(
            " This package holds {in_evidence} of the {number} records."
        ));
    }
    text
}

fn detection_statement(address: IpAddr, detection: &Detection) -> String {
    let verdict = match detection.verdict {
        Verdict::Malicious => "malicious",
        Verdict::Suspicious | Verdict::Benign => "suspicious",
    };
    format!(
        "A detection rule of the reporter classified activity from the address {address} as \
         {verdict}. The time of the detection was {}.",
        time_text(detection.time)
    )
}

fn qualifies(verdict: Verdict, include_suspicious: bool) -> bool {
    match verdict {
        Verdict::Malicious => true,
        Verdict::Suspicious => include_suspicious,
        Verdict::Benign => false,
    }
}

fn event_address(event: &Event) -> Option<IpAddr> {
    event.actor.ip.map(canonical_address)
}

/// Returns `true` if the audit record is the record of `detection`.
fn records_detection(record: &AuditRecord, detection: DetectionId) -> bool {
    let id = detection.to_string();
    record.kind == AuditKind::Detection
        && record
            .evidence
            .iter()
            .any(|link| link.kind == EvidenceKind::Detection && link.id == id)
}

/// Returns the item identifiers as text, with each run of items as a range.
fn id_ranges(positions: &[usize], items: &[EvidenceItem]) -> String {
    let id = |position: usize| items.get(position).map_or("?", |item| item.id.as_str());
    let mut parts: Vec<String> = Vec::new();
    let mut run: Option<(usize, usize)> = None;
    let close = |run: (usize, usize), parts: &mut Vec<String>| {
        if run.0 == run.1 {
            parts.push(id(run.0).to_owned());
        } else {
            parts.push(format!("{} to {}", id(run.0), id(run.1)));
        }
    };
    for position in positions {
        run = match run {
            Some((start, end)) if *position == end + 1 => Some((start, *position)),
            Some(open) => {
                close(open, &mut parts);
                Some((*position, *position))
            }
            None => Some((*position, *position)),
        };
    }
    if let Some(open) = run {
        close(open, &mut parts);
    }
    parts.join(", ")
}

fn increment(counts: &mut BTreeMap<String, usize>, value: &str) {
    *counts.entry(value.to_owned()).or_insert(0) += 1;
}

fn observed(counts: BTreeMap<String, usize>) -> Vec<ObservedValue> {
    counts
        .into_iter()
        .map(|(value, records)| ObservedValue { value, records })
        .collect()
}

fn port_of(value: &Value) -> Option<u16> {
    match value {
        Value::Number(number) => number.as_u64().and_then(|port| u16::try_from(port).ok()),
        Value::String(text) => text.trim().parse::<u16>().ok(),
        _ => None,
    }
}

/// The counts of the values that the evidence items of one address show.
#[derive(Default)]
struct Seen {
    user_agents: BTreeMap<String, usize>,
    fingerprints: BTreeMap<String, usize>,
    ports: BTreeMap<u16, usize>,
}

impl Seen {
    /// Counts the values of one minimized event.
    fn add(&mut self, fields: &Map<String, Value>) {
        if let Some(user_agent) = fields.get("user_agent").and_then(Value::as_str) {
            increment(&mut self.user_agents, user_agent);
        }
        let attributes = fields.get("attributes").and_then(Value::as_object);
        if let Some(fingerprint) = attributes
            .and_then(|attributes| attributes.get(attr::CLIENT_FINGERPRINT))
            .and_then(Value::as_str)
        {
            increment(&mut self.fingerprints, fingerprint);
        }
        if let Some(port) = attributes
            .and_then(|attributes| attributes.get(attr::DESTINATION_PORT))
            .and_then(port_of)
        {
            *self.ports.entry(port).or_insert(0) += 1;
        }
    }
}

impl<'a> Section<'a> {
    /// Makes the section of one address and selects the records that become evidence.
    fn new(
        address: IpAddr,
        records: Vec<&'a Event>,
        detections: Vec<&'a Detection>,
        options: &AbuseReportOptions,
        notes: &mut Vec<BuildNote>,
    ) -> Self {
        let limit = options.max_evidence_items;
        let mut included: HashSet<EventId> = HashSet::with_capacity(records.len().min(limit));
        if records.len() <= limit {
            included.extend(records.iter().map(|event| event.id));
        } else {
            // The records that a detection cites come first. Then one record of each
            // type of activity. Then the remaining records in time order.
            let cited: HashSet<EventId> = detections
                .iter()
                .flat_map(|detection| detection.event_ids.iter().copied())
                .collect();
            let mut groups: HashSet<(String, Outcome)> = HashSet::new();
            let first_of_group: HashSet<EventId> = records
                .iter()
                .filter(|event| {
                    groups.insert((
                        shown_action(&event.action, options.disclose_decoys),
                        event.outcome,
                    ))
                })
                .map(|event| event.id)
                .collect();
            let passes: [&dyn Fn(&Event) -> bool; 3] = [
                &|event| cited.contains(&event.id),
                &|event| first_of_group.contains(&event.id),
                &|_| true,
            ];
            for pass in passes {
                for event in &records {
                    if included.len() >= limit {
                        break;
                    }
                    if pass(event) {
                        included.insert(event.id);
                    }
                }
            }
            notes.push(BuildNote::EvidenceLimited {
                address,
                records: records.len(),
                included: included.len(),
            });
        }
        Self {
            address,
            records,
            included,
            detections,
        }
    }
}

/// Makes the fields of the evidence item for an audit record.
///
/// The item holds no text of the record. The hash of the record commits the reporter to
/// the full record, which stays in the audit log of the reporter.
fn audit_fields(record: &AuditRecord, detections: &BTreeSet<String>) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("type".to_owned(), Value::String("audit_record".to_owned()));
    fields.insert("record".to_owned(), Value::String(record.id.to_string()));
    fields.insert("sequence".to_owned(), Value::from(record.sequence));
    fields.insert("time".to_owned(), Value::String(time_text(record.time)));
    fields.insert("audit_kind".to_owned(), Value::String(token(&record.kind)));
    fields.insert(
        "record_hash".to_owned(),
        Value::String(clean(&record.hash, MAX_TOKEN_CHARS)),
    );
    fields.insert(
        "detections".to_owned(),
        Value::Array(detections.iter().cloned().map(Value::String).collect()),
    );
    fields
}

/// Makes one report from the sections of its addresses.
///
/// Returns `None` if the sections give no claim.
fn assemble(
    subject: ReportSubject,
    sections: &[&Section<'_>],
    context: &Context<'_>,
    notes: &mut Vec<BuildNote>,
) -> Result<Option<AbuseReport>, ShareError> {
    let options = context.options;
    let subject_addresses: Vec<IpAddr> = sections.iter().map(|section| section.address).collect();
    let mut minimizer = Minimizer::new(
        &options.allow,
        context.redactor,
        options.disclose_decoys,
        subject_addresses,
    );

    // The evidence: the records of each address in time order, then the audit records.
    let mut drafts: Vec<(EvidenceItemKind, Map<String, Value>)> = Vec::new();
    let mut event_items: HashMap<EventId, usize> = HashMap::new();
    let mut seen: Vec<Seen> = Vec::with_capacity(sections.len());
    for section in sections {
        let mut values = Seen::default();
        for event in &section.records {
            if !section.included.contains(&event.id) {
                continue;
            }
            let fields = minimizer.event(event);
            values.add(&fields);
            event_items.insert(event.id, drafts.len());
            drafts.push((EvidenceItemKind::Event, fields));
        }
        seen.push(values);
    }
    let mut audit_items: HashMap<AuditId, usize> = HashMap::new();
    for record in &context.audit_records {
        let detections: BTreeSet<String> = sections
            .iter()
            .flat_map(|section| section.detections.iter())
            .filter(|detection| records_detection(record, detection.id))
            .map(|detection| detection.id.to_string())
            .collect();
        if !detections.is_empty() && !audit_items.contains_key(&record.id) {
            audit_items.insert(record.id, drafts.len());
            drafts.push((
                EvidenceItemKind::AuditRecord,
                audit_fields(record, &detections),
            ));
        }
    }
    let total = drafts.len();
    let evidence: Vec<EvidenceItem> = drafts
        .into_iter()
        .enumerate()
        .map(|(position, (kind, fields))| {
            EvidenceItem::new(item_id(position + 1, total), kind, fields)
        })
        .collect();

    let mut claim_number = 0_usize;
    let mut make_claim = |kind: ClaimKind,
                          address: IpAddr,
                          title: String,
                          statement: String,
                          shown: Option<String>,
                          times: (DateTime<Utc>, DateTime<Utc>),
                          records: usize,
                          detected: Option<(Verdict, Vec<Technique>)>,
                          positions: &[usize]|
     -> Claim {
        claim_number += 1;
        let cited = |position: &usize| evidence.get(*position);
        Claim {
            id: format!("C{claim_number}"),
            kind,
            address,
            title,
            statement,
            action: shown,
            first_seen: times.0,
            last_seen: times.1,
            records,
            verdict: detected.as_ref().map(|(verdict, _)| *verdict),
            techniques: detected
                .map(|(_, techniques)| techniques)
                .unwrap_or_default(),
            evidence: positions
                .iter()
                .filter_map(cited)
                .map(|item| item.id.clone())
                .collect(),
            excerpt: positions
                .iter()
                .filter_map(cited)
                .take(options.excerpt_lines)
                .map(|item| item.content.clone())
                .collect(),
        }
    };

    let mut activities: Vec<AddressActivity> = Vec::with_capacity(sections.len());
    let mut all_techniques = TechniqueSet::default();
    for (section, values) in sections.iter().zip(seen) {
        let address = section.address;
        let mut claims: Vec<Claim> = Vec::new();

        // One activity claim for each action and result, in the order of the first record.
        let mut order: Vec<(String, Outcome)> = Vec::new();
        let mut groups: HashMap<(String, Outcome), Vec<&Event>> = HashMap::new();
        for event in &section.records {
            let key = (
                shown_action(&event.action, options.disclose_decoys),
                event.outcome,
            );
            if !groups.contains_key(&key) {
                order.push(key.clone());
            }
            groups.entry(key).or_default().push(event);
        }
        for key in order {
            let Some(records) = groups.get(&key) else {
                continue;
            };
            let positions: Vec<usize> = records
                .iter()
                .filter_map(|event| event_items.get(&event.id).copied())
                .collect();
            let (Some(first), Some(last)) = (records.first(), records.last()) else {
                continue;
            };
            if positions.is_empty() {
                notes.push(BuildNote::ActivityWithoutEvidence {
                    address,
                    records: records.len(),
                });
                continue;
            }
            let (shown, outcome) = key;
            let words = action_phrase(&shown);
            claims.push(make_claim(
                ClaimKind::Activity,
                address,
                activity_title(&words, outcome, records.len()),
                activity_statement(address, &words, outcome, records, positions.len()),
                Some(shown),
                (first.time, last.time),
                records.len(),
                None,
                &positions,
            ));
        }

        // One detection claim for each detection that has evidence for this address.
        let mut detections = section.detections.clone();
        detections.sort_by_key(|detection| (detection.time, detection.id));
        let section_times: HashMap<EventId, DateTime<Utc>> = section
            .records
            .iter()
            .filter(|event| event_items.contains_key(&event.id))
            .map(|event| (event.id, event.time))
            .collect();
        for detection in detections {
            let mut positions: BTreeSet<usize> = detection
                .event_ids
                .iter()
                .filter(|id| section_times.contains_key(id))
                .filter_map(|id| event_items.get(id).copied())
                .collect();
            let cited_records = positions.len();
            positions.extend(
                context
                    .audit_records
                    .iter()
                    .filter(|record| records_detection(record, detection.id))
                    .filter_map(|record| audit_items.get(&record.id).copied()),
            );
            if positions.is_empty() {
                notes.push(BuildNote::DetectionWithoutEvidence {
                    address,
                    detection: detection.id,
                });
                continue;
            }
            let mut techniques = TechniqueSet::default();
            for technique in &detection.attack {
                techniques.add(technique, detection.tier, |text| {
                    context.redactor.redact(text)
                });
            }
            let techniques = techniques.into_vec();
            all_techniques.merge(&techniques);
            let times: Vec<DateTime<Utc>> = detection
                .event_ids
                .iter()
                .filter_map(|id| section_times.get(id).copied())
                .collect();
            let first = times.iter().min().copied().unwrap_or(detection.time);
            let last = times.iter().max().copied().unwrap_or(detection.time);
            let positions: Vec<usize> = positions.into_iter().collect();
            let title = match detection.verdict {
                Verdict::Malicious => "Detection: activity classified as malicious",
                Verdict::Suspicious | Verdict::Benign => {
                    "Detection: activity classified as suspicious"
                }
            };
            claims.push(make_claim(
                ClaimKind::Detection,
                address,
                title.to_owned(),
                detection_statement(address, detection),
                None,
                (first, last),
                cited_records,
                Some((detection.verdict, techniques)),
                &positions,
            ));
        }

        let (Some(first), Some(last)) = (section.records.first(), section.records.last()) else {
            continue;
        };
        if claims.is_empty() {
            continue;
        }
        activities.push(AddressActivity {
            address,
            first_seen: first.time,
            last_seen: last.time,
            records: section.records.len(),
            records_in_evidence: section.included.len(),
            ports: values
                .ports
                .into_iter()
                .map(|(port, records)| ObservedPort { port, records })
                .collect(),
            user_agents: observed(values.user_agents),
            client_fingerprints: observed(values.fingerprints),
            claims,
        });
    }

    let (Some(first_seen), Some(last_seen)) = (
        activities.iter().map(|activity| activity.first_seen).min(),
        activities.iter().map(|activity| activity.last_seen).max(),
    ) else {
        return Ok(None);
    };
    let report = AbuseReport {
        format: REPORT_FORMAT.to_owned(),
        reference: format!("AEGIS-{}", context.incident.id),
        subject,
        generated_at: options.generated_at,
        reporter: options.reporter.as_ref().map(|reporter| Reporter {
            name: clean(&reporter.name, MAX_TOKEN_CHARS),
            contact: reporter
                .contact
                .as_deref()
                .map(|contact| clean(contact, MAX_TOKEN_CHARS)),
        }),
        first_seen,
        last_seen,
        addresses: activities,
        techniques: all_techniques.into_vec(),
        manifest: EvidenceManifest::for_items(&evidence),
        evidence,
        notice: NOTICE.to_owned(),
    };
    report.check()?;
    Ok(Some(report))
}

impl AbuseReport {
    /// Makes the abuse reports of one incident.
    ///
    /// `events` are log records from the time of the incident. The builder uses only the
    /// records from the attacker addresses. `audit_records` are records of the audit log.
    /// The builder uses a record that seals a detection of the incident as evidence that
    /// the detection occurred.
    ///
    /// An address is an attacker address if a `malicious` detection of the incident
    /// names it, or cites a record from it. The [`AddressPolicy`] of the options then
    /// removes the addresses of the operator and the addresses that are not public.
    ///
    /// The package can have no report. The notes then give the cause.
    ///
    /// # Errors
    ///
    /// - [`ShareError::NotReportable`] if the incident has the state `false_positive`.
    /// - [`ShareError::AuditIntegrity`] if an audit record does not have the hash of its
    ///   contents. A changed audit log is not evidence.
    /// - [`ShareError::InvalidOption`] if an option is not valid.
    /// - [`ShareError::Encode`] if the table of masked values cannot be made.
    pub fn build(
        incident: &Incident,
        events: &[Event],
        audit_records: &[AuditRecord],
        options: &AbuseReportOptions,
    ) -> Result<AbuseReportPackage, ShareError> {
        options.validate()?;
        if incident.status == IncidentStatus::FalsePositive {
            return Err(ShareError::NotReportable(
                "the state of the incident is false_positive".to_owned(),
            ));
        }
        for record in audit_records {
            let expected = record
                .compute_hash()
                .map_err(|error| ShareError::encode("audit record", error))?;
            if expected != record.hash {
                return Err(ShareError::AuditIntegrity {
                    sequence: record.sequence,
                });
            }
        }
        let mut notes: Vec<BuildNote> = Vec::new();

        // The events with no duplicates, in time order.
        let mut by_id: HashMap<EventId, &Event> = HashMap::with_capacity(events.len());
        for event in events {
            by_id.entry(event.id).or_insert(event);
        }
        let mut ordered: Vec<&Event> = by_id.values().copied().collect();
        ordered.sort_by_key(|event| (event.time, event.id));

        // The addresses that a used detection names, or cites a record from.
        let mut linked: BTreeMap<IpAddr, Vec<&Detection>> = BTreeMap::new();
        let mut times: Vec<DateTime<Utc>> = Vec::new();
        let mut known_detections: HashSet<DetectionId> = HashSet::new();
        for detection in &incident.detections {
            // A repeated detection makes no second claim.
            if !known_detections.insert(detection.id) {
                continue;
            }
            if !qualifies(detection.verdict, options.include_suspicious) {
                notes.push(BuildNote::DetectionNotUsed {
                    detection: detection.id,
                    verdict: detection.verdict,
                });
                continue;
            }
            times.push(detection.time);
            let mut addresses: BTreeSet<IpAddr> = BTreeSet::new();
            for entity in &detection.entities {
                if entity.kind != EntityKind::IpAddress {
                    continue;
                }
                match entity.id.trim().parse::<IpAddr>() {
                    Ok(address) => {
                        addresses.insert(canonical_address(address));
                    }
                    Err(_) => notes.push(BuildNote::EntityNotAnAddress {
                        detection: detection.id,
                    }),
                }
            }
            for id in &detection.event_ids {
                if let Some(event) = by_id.get(id) {
                    times.push(event.time);
                    addresses.extend(event_address(event));
                }
            }
            for address in addresses {
                linked.entry(address).or_default().push(detection);
            }
        }

        let in_window: Box<dyn Fn(DateTime<Utc>) -> bool> = match options.window {
            Some(window) => Box::new(move |time| window.contains(time)),
            None => {
                let (Some(first), Some(last)) = (times.iter().min(), times.iter().max()) else {
                    return Ok(AbuseReportPackage {
                        reports: Vec::new(),
                        notes,
                    });
                };
                let start = first
                    .checked_sub_signed(options.activity_margin)
                    .unwrap_or(DateTime::<Utc>::MIN_UTC);
                let end = last
                    .checked_add_signed(options.activity_margin)
                    .unwrap_or(DateTime::<Utc>::MAX_UTC);
                Box::new(move |time| start <= time && time <= end)
            }
        };

        let redactor =
            Redactor::for_inputs(Some(incident), &incident.detections, events, &options.allow)?;
        let mut sections: Vec<Section<'_>> = Vec::new();
        for (address, detections) in linked {
            if !options.addresses.permits(address) {
                notes.push(BuildNote::AddressExcluded {
                    address,
                    class: options.addresses.classify(address),
                });
                continue;
            }
            let records: Vec<&Event> = ordered
                .iter()
                .copied()
                .filter(|event| event_address(event) == Some(address) && in_window(event.time))
                .collect();
            if records.is_empty() {
                notes.push(BuildNote::AddressWithoutRecords { address });
                continue;
            }
            sections.push(Section::new(
                address, records, detections, options, &mut notes,
            ));
        }

        let mut audit: Vec<&AuditRecord> = audit_records.iter().collect();
        audit.sort_by_key(|record| (record.sequence, record.id));
        let context = Context {
            incident,
            audit_records: audit,
            options,
            redactor: &redactor,
        };
        let mut reports: Vec<AbuseReport> = Vec::new();
        for section in &sections {
            let subject = ReportSubject::Address {
                address: section.address,
            };
            reports.extend(assemble(subject, &[section], &context, &mut notes)?);
        }
        let mut networks: BTreeMap<&HostingNetwork, Vec<&Section<'_>>> = BTreeMap::new();
        for section in &sections {
            if let Some(network) = options.networks.lookup(section.address) {
                networks.entry(network).or_default().push(section);
            }
        }
        for (network, members) in networks {
            let subject = ReportSubject::Network {
                name: clean(&network.name, MAX_TOKEN_CHARS),
                abuse_contact: network
                    .abuse_contact
                    .as_deref()
                    .map(|contact| clean(contact, MAX_TOKEN_CHARS)),
                addresses: members.iter().map(|section| section.address).collect(),
            };
            reports.extend(assemble(subject, &members, &context, &mut notes)?);
        }

        // A network report repeats the notes of its address reports.
        let mut unique: Vec<BuildNote> = Vec::with_capacity(notes.len());
        for note in notes {
            if !unique.contains(&note) {
                unique.push(note);
            }
        }
        Ok(AbuseReportPackage {
            reports,
            notes: unique,
        })
    }

    /// Returns all claims of the report, in order.
    pub fn claims(&self) -> impl Iterator<Item = &Claim> {
        self.addresses
            .iter()
            .flat_map(|activity| activity.claims.iter())
    }

    /// Checks the rules of a report: each claim has evidence, each cited item is in the
    /// report, and the manifest agrees with the items.
    ///
    /// The builder runs this check on each report that it returns.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::ClaimWithoutEvidence`] for a claim with no evidence item or
    /// with an item that the report does not hold. Returns [`ShareError::Manifest`] if
    /// the manifest does not agree with the items.
    pub fn check(&self) -> Result<(), ShareError> {
        let known: HashSet<&str> = self.evidence.iter().map(|item| item.id.as_str()).collect();
        for claim in self.claims() {
            let cited = claim.evidence.iter().all(|id| known.contains(id.as_str()));
            if claim.evidence.is_empty() || claim.excerpt.is_empty() || !cited {
                return Err(ShareError::ClaimWithoutEvidence {
                    claim: claim.id.clone(),
                });
            }
        }
        self.manifest.verify_items(&self.evidence)
    }

    /// Returns the evidence file: one evidence item in each line.
    #[must_use]
    pub fn evidence_jsonl(&self) -> String {
        evidence_jsonl(&self.evidence)
    }

    /// Returns the four files of the report: `report.md`, `report.json`,
    /// `evidence.jsonl`, and `manifest.json`.
    ///
    /// The function writes no file and sends nothing. The operator decides if a report
    /// leaves the organization, and how.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::Encode`] if the report cannot be encoded.
    pub fn files(&self) -> Result<Vec<ReportFile>, ShareError> {
        Ok(vec![
            ReportFile {
                name: "report.md",
                content: self.to_markdown(),
            },
            ReportFile {
                name: "report.json",
                content: self.to_json_string()?,
            },
            ReportFile {
                name: EVIDENCE_FILE_NAME,
                content: self.evidence_jsonl(),
            },
            ReportFile {
                name: "manifest.json",
                content: self.manifest.to_json_string()?,
            },
        ])
    }

    /// Returns the report as a JSON value.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::Encode`] if the report cannot be encoded.
    pub fn to_json(&self) -> Result<Value, ShareError> {
        serde_json::to_value(self).map_err(|error| ShareError::encode("abuse report", error))
    }

    /// Returns the report as JSON text.
    ///
    /// The text holds only printable ASCII. Each other character is a `\uXXXX` escape,
    /// and so are `<`, `>`, `&`, and the backtick. The object keys are in byte order.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::Encode`] if the report cannot be encoded.
    pub fn to_json_string(&self) -> Result<String, ShareError> {
        Ok(json_pretty(&self.to_json()?))
    }

    /// Returns the report as Markdown, for the body of a message to an abuse desk.
    ///
    /// Text from a log record appears only in code spans and in code blocks, where
    /// markup has no effect.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let positions: HashMap<&str, usize> = self
            .evidence
            .iter()
            .enumerate()
            .map(|(position, item)| (item.id.as_str(), position))
            .collect();
        let records: usize = self.addresses.iter().map(|activity| activity.records).sum();
        let (title, subject) = match &self.subject {
            ReportSubject::Address { address } => (
                format!("activity from {address}"),
                format!("IP address {address}"),
            ),
            ReportSubject::Network {
                name, addresses, ..
            } => (
                format!("activity from {}", md_text(name, MAX_TOKEN_CHARS)),
                format!(
                    "Network {} ({})",
                    md_text(name, MAX_TOKEN_CHARS),
                    counted(addresses.len(), "address", "addresses")
                ),
            ),
        };
        let mut text = format!("# Abuse report: {title}\n\n");
        text.push_str("| Field | Value |\n| --- | --- |\n");
        let mut fields: Vec<(&str, String)> =
            vec![("Reference", self.reference.clone()), ("Subject", subject)];
        if let ReportSubject::Network {
            abuse_contact: Some(contact),
            ..
        } = &self.subject
        {
            fields.push(("Abuse contact", md_text(contact, MAX_TOKEN_CHARS)));
        }
        fields.push(("First activity (UTC)", time_text(self.first_seen)));
        fields.push(("Last activity (UTC)", time_text(self.last_seen)));
        fields.push(("Log records", records.to_string()));
        fields.push(("Report time (UTC)", time_text(self.generated_at)));
        fields.push((
            "Reporter",
            match &self.reporter {
                Some(reporter) => match &reporter.contact {
                    Some(contact) => format!(
                        "{} ({})",
                        md_text(&reporter.name, MAX_TOKEN_CHARS),
                        md_text(contact, MAX_TOKEN_CHARS)
                    ),
                    None => md_text(&reporter.name, MAX_TOKEN_CHARS),
                },
                None => "The sender of this message".to_owned(),
            },
        ));
        for (name, value) in fields {
            text.push_str(&format!("| {name} | {value} |\n"));
        }
        text.push_str(&format!("\nAll times are in UTC. {NOTICE}\n"));

        text.push_str("\n## Summary\n\n");
        let verdicts: Vec<Verdict> = self.claims().filter_map(|claim| claim.verdict).collect();
        text.push_str(&format!(
            "Systems of the reporter recorded {} from {} between {} and {}.",
            counted(records, "log record", "log records"),
            counted(self.addresses.len(), "address", "addresses"),
            time_text(self.first_seen),
            time_text(self.last_seen)
        ));
        if verdicts.contains(&Verdict::Malicious) {
            text.push_str(
                " Detection rules of the reporter classified a part of this activity as malicious.",
            );
        } else if !verdicts.is_empty() {
            text.push_str(
                " Detection rules of the reporter classified a part of this activity as suspicious.",
            );
        }
        text.push_str(" Examine this activity and stop it. Give the reference in each reply.\n");

        text.push_str("\n## What occurred\n");
        for activity in &self.addresses {
            text.push_str(&format!("\n### Address {}\n", activity.address));
            for claim in &activity.claims {
                text.push_str(&format!("\n#### {}. {}\n\n", claim.id, claim.title));
                text.push_str(&claim.statement);
                text.push_str("\n\n");
                if let Some(shown) = &claim.action {
                    text.push_str(&format!(
                        "- Action name: {}\n",
                        md_code(shown, MAX_TOKEN_CHARS)
                    ));
                }
                for technique in &claim.techniques {
                    text.push_str(&format!("- ATT&CK: {}\n", technique_text(technique)));
                }
                let cited: Vec<usize> = claim
                    .evidence
                    .iter()
                    .filter_map(|id| positions.get(id.as_str()).copied())
                    .collect();
                text.push_str(&format!(
                    "- Evidence: {} ({})\n",
                    id_ranges(&cited, &self.evidence),
                    counted(cited.len(), "item", "items")
                ));
                text.push_str(&format!(
                    "- Log excerpt ({} of {}):\n\n```json\n",
                    claim.excerpt.len(),
                    counted(cited.len(), "item", "items")
                ));
                for line in &claim.excerpt {
                    text.push_str(line);
                    text.push('\n');
                }
                text.push_str("```\n");
            }
        }

        text.push_str("\n## Addresses and ports\n\n");
        for activity in &self.addresses {
            text.push_str(&format!(
                "- {}: {}, from {} to {}.",
                activity.address,
                counted(activity.records, "log record", "log records"),
                time_text(activity.first_seen),
                time_text(activity.last_seen)
            ));
            if activity.ports.is_empty() {
                text.push_str(" The log records give no port number.\n");
            } else {
                let ports: Vec<String> = activity
                    .ports
                    .iter()
                    .map(|port| {
                        format!(
                            "{} ({})",
                            port.port,
                            counted(port.records, "record", "records")
                        )
                    })
                    .collect();
                text.push_str(&format!(" Destination ports: {}.\n", ports.join(", ")));
            }
        }

        text.push_str("\n## User agents and client fingerprints\n\n");
        let mut values = 0_usize;
        for activity in &self.addresses {
            for (label, found) in [
                ("User agent", &activity.user_agents),
                ("Client fingerprint", &activity.client_fingerprints),
            ] {
                for value in found {
                    values += 1;
                    text.push_str(&format!(
                        "- {}, {label}: {} ({})\n",
                        activity.address,
                        md_code(&value.value, MAX_TOKEN_CHARS.saturating_mul(4)),
                        counted(value.records, "record", "records")
                    ));
                }
            }
        }
        if values == 0 {
            text.push_str("The log records give no user agent and no client fingerprint.\n");
        } else {
            text.push_str(
                "\nA user agent is text that the client sends. A client fingerprint is a \
                 heuristic. The two values do not identify a person.\n",
            );
        }

        text.push_str("\n## ATT&CK techniques\n\n");
        if self.techniques.is_empty() {
            text.push_str("The report has no detection claim with an ATT&CK technique.\n");
        } else {
            for technique in &self.techniques {
                let claims: Vec<&str> = self
                    .claims()
                    .filter(|claim| {
                        claim
                            .techniques
                            .iter()
                            .any(|found| found.id == technique.id)
                    })
                    .map(|claim| claim.id.as_str())
                    .collect();
                text.push_str(&format!(
                    "- {}, <{}>, claims {}\n",
                    technique_text(technique),
                    technique.url,
                    claims.join(", ")
                ));
            }
        }

        text.push_str("\n## Evidence and integrity\n\n");
        text.push_str(
            "Each evidence item is one log record of the reporter with the least data. A value \
             such as `masked-3` replaces an identifier of the reporter. The same value is the \
             same entity. The text `[masked]`, `[secret removed]`, or `[address removed]` \
             replaces data that the reporter does not share. Text such as `{U+001B}` replaces a \
             character that is not safe to show.\n\n",
        );
        text.push_str(&format!(
            "The package holds {} in the file `{EVIDENCE_FILE_NAME}`, one item in each line. \
             The file `manifest.json` holds the SHA-256 of each item. To check an item, \
             compute the SHA-256 of its line without the line feed.\n\n",
            counted(self.evidence.len(), "evidence item", "evidence items")
        ));
        text.push_str(&format!(
            "- SHA-256 of `{EVIDENCE_FILE_NAME}` ({} bytes): `{}`\n\n",
            self.manifest.file_bytes, self.manifest.file_sha256
        ));
        text.push_str("The table gives the hash of each item in an excerpt.\n\n");
        text.push_str("| Item | SHA-256 |\n| --- | --- |\n");
        let mut shown: BTreeSet<usize> = BTreeSet::new();
        for claim in self.claims() {
            shown.extend(
                claim
                    .evidence
                    .iter()
                    .take(claim.excerpt.len())
                    .filter_map(|id| positions.get(id.as_str()).copied()),
            );
        }
        for item in shown
            .into_iter()
            .filter_map(|position| self.evidence.get(position))
        {
            text.push_str(&format!("| {} | `{}` |\n", item.id, item.sha256));
        }
        text
    }
}

/// Returns a technique as Markdown text: the identifier, the name, and the tactics.
fn technique_text(technique: &Technique) -> String {
    let mut text = technique.id.clone();
    if let Some(name) = &technique.name {
        text.push(' ');
        text.push_str(&md_text(name, MAX_TOKEN_CHARS));
    }
    if !technique.tactics.is_empty() {
        text.push_str(&format!(" ({})", technique.tactics.join(", ")));
    }
    text
}
