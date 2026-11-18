//! Documents that an AEGIS operator can send to other defenders.
//!
//! The crate turns what AEGIS saw into two types of documents:
//!
//! - An **abuse report** for one incident: [`AbuseReport::build`]. There is one report
//!   for each attacker address, and one for each hosting network that the caller names.
//!   A report says what occurred in plain words. Each claim names its evidence. A
//!   manifest gives the SHA-256 of each evidence item.
//! - An **indicator export**: [`IndicatorSet::collect`], then
//!   [`IndicatorSet::to_stix`] for a STIX 2.1 bundle or [`IndicatorSet::to_csv`] for a
//!   CSV file.
//!
//! The crate makes documents only. It opens no connection and writes no file. The
//! operator reads each document and decides if it leaves the organization.
//!
//! # Privacy rules
//!
//! - A document keeps the least data. The builder masks the identifiers of the
//!   operator, and it removes names, tenants, sessions, and the original records. An
//!   [`AllowList`] selects what stays.
//! - The builder replaces each part of kept text that looks like a secret. No option
//!   turns that off.
//! - A document never names an address of the operator, a private address, or a
//!   reserved address. Refer to [`AddressPolicy`].
//! - A report has no claim without an evidence item.
//! - A document never says who did the activity. It gives log data. It copies no text
//!   that a model or an analyst wrote.
//! - Text from an event is untrusted. In Markdown, it appears only in code spans and
//!   code blocks. In JSON, each character that is not printable ASCII is an escape.
//!
//! # Example
//!
//! ```
//! use aegis_contracts::common::{DetectionId, EntityKind, EntityRef, IncidentId, Severity};
//! use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
//! use aegis_contracts::event::{Actor, Event, EventClass, EventSource, Outcome, action};
//! use aegis_contracts::incident::{Incident, IncidentStatus};
//! use aegis_share::{
//!     AbuseReport, AbuseReportOptions, AddressPolicy, IndicatorOptions, IndicatorSet,
//!     StixOptions, Tlp,
//! };
//! use chrono::{TimeZone, Utc};
//!
//! // The example uses an address from a documentation range, so it must permit those
//! // ranges. Do not permit them for a document that you send.
//! let addresses = AddressPolicy::new().with_documentation_ranges();
//! let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 0).unwrap();
//! let event = Event::new(
//!     time,
//!     EventSource::new("idp", "example", "identity"),
//!     EventClass::Authentication,
//!     action::SIGN_IN,
//!     Actor::new(EntityKind::User, "user-dana")
//!         .with_ip("203.0.113.50".parse()?)
//!         .with_user_agent("python-httpx/0.27.0"),
//! )
//! .with_outcome(Outcome::Failure);
//! let detection = Detection {
//!     id: DetectionId::new(),
//!     rule_id: "aegis.velocity.sign_in_burst".to_owned(),
//!     title: "Sign-in burst from one address".to_owned(),
//!     description: "A password spray.".to_owned(),
//!     severity: Severity::High,
//!     verdict: Verdict::Malicious,
//!     tier: DetectionTier::Deterministic,
//!     time,
//!     attack: vec![AttackTechnique::new(
//!         "credential-access",
//!         "T1110.003",
//!         "Password Spraying",
//!     )],
//!     event_ids: vec![event.id],
//!     entities: vec![EntityRef::new(EntityKind::IpAddress, "203.0.113.50")],
//!     tenant: None,
//!     attributes: Default::default(),
//! };
//! let incident = Incident {
//!     id: IncidentId::new(),
//!     title: "Password spray".to_owned(),
//!     summary: String::new(),
//!     severity: Severity::High,
//!     status: IncidentStatus::Open,
//!     created_at: time,
//!     updated_at: time,
//!     tenant: None,
//!     detections: vec![detection],
//!     entities: Vec::new(),
//!     attack: Vec::new(),
//!     timeline: Vec::new(),
//! };
//! let events = [event];
//!
//! // One abuse report for the one attacker address.
//! let options = AbuseReportOptions::new(time).with_addresses(addresses.clone());
//! let package = AbuseReport::build(&incident, &events, &[], &options)?;
//! assert_eq!(package.reports.len(), 1);
//! let report = &package.reports[0];
//! let markdown = report.to_markdown();
//! assert!(markdown.starts_with("# Abuse report: activity from 203.0.113.50\n"));
//! // The identifier of the user of the operator is not in the report.
//! assert!(!markdown.contains("user-dana"));
//! assert!(!report.to_json_string()?.contains("user-dana"));
//! report.manifest.verify_file(&report.evidence_jsonl())?;
//!
//! // The indicators of the same detection, as STIX 2.1 and as CSV.
//! let options = IndicatorOptions::new().with_addresses(addresses);
//! let indicators = IndicatorSet::collect(&incident.detections, &events, &options)?;
//! let bundle = indicators.to_stix(&StixOptions::new(Tlp::Amber, time))?;
//! assert_eq!(bundle["type"], "bundle");
//! assert_eq!(
//!     bundle["objects"][1]["pattern"],
//!     "[ipv4-addr:value = '203.0.113.50']"
//! );
//! assert_eq!(indicators.to_csv(Tlp::Amber).lines().count(), 3);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Modules
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`report`] | The abuse report package. |
//! | [`evidence`] | Evidence items and the manifest. |
//! | [`indicator`] | The indicators of detections and decoy events. |
//! | [`stix`] | The STIX 2.1 form of the indicators. |
//! | [`csv`] | The CSV form of the indicators. |
//! | [`minimize`] | The allow list and the masking rules. |
//! | [`address`] | The rules for which addresses a document can name. |
//! | [`attack`] | ATT&CK techniques in the documents. |
//! | [`error`] | The error type. |

pub mod address;
pub mod attack;
pub mod csv;
pub mod error;
pub mod evidence;
pub mod indicator;
pub mod minimize;
pub mod report;
mod secrets;
pub mod stix;
mod text;

pub use address::{AddressClass, AddressPolicy, canonical_address};
pub use attack::Technique;
pub use csv::CSV_HEADER;
pub use error::ShareError;
pub use evidence::{
    EVIDENCE_FILE_NAME, EvidenceItem, EvidenceItemKind, EvidenceManifest, HASH_ALGORITHM,
    ManifestEntry, evidence_jsonl,
};
pub use indicator::{
    Indicator, IndicatorBasis, IndicatorKind, IndicatorOptions, IndicatorSet, MIN_USER_AGENT_CHARS,
    SkipReason, SkippedValue,
};
pub use minimize::{AllowList, DEFAULT_ATTRIBUTES, Field, SOURCE_PORT};
pub use report::{
    AbuseReport, AbuseReportOptions, AbuseReportPackage, AddressActivity, BuildNote, Claim,
    ClaimKind, HostingNetwork, NOTICE, NetworkMap, ObservedPort, ObservedValue, REPORT_FORMAT,
    ReportFile, ReportSubject, Reporter,
};
pub use stix::{DEFAULT_NAMESPACE, DEFAULT_VALID_DAYS, StixOptions, Tlp, stix_pattern};

/// Compiles the examples of `README.md` as documentation tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;
