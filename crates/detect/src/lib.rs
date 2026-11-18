//! Detection and correlation for AEGIS.
//!
//! This crate reads the normalized [`Event`](aegis_contracts::Event) stream, finds
//! attacks, and folds the findings into [`Incident`](aegis_contracts::Incident) values. It
//! talks to other subsystems only through the contracts in `aegis-contracts`.
//!
//! Detection has two tiers:
//!
//! - **Tier 1** is deterministic and uses no model: Sigma rules, indicator matches, and
//!   velocity detectors.
//! - **Tier 2** asks a model about the detections that tier 1 marks as `suspicious`. A
//!   `malicious` detection and an event with no detection never reach the model.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`engine`] | [`DetectionEngine`]: the two tiers and the correlator as one unit, and the bus runner. |
//! | [`sigma`] | The Sigma rule engine. The module documentation lists the supported parts of Sigma. |
//! | [`ioc`] | The indicator store: addresses, networks, domains, user agents, application identifiers. |
//! | [`velocity`] | The stateful detectors: sign-in burst, privileged self-assignment, credential after grant, impossible speed. |
//! | [`llm`] | [`LlmTriage`]: tier 2. |
//! | [`correlate`] | [`Correlator`]: detections to incidents. |
//! | [`pack`] | [`RulePack`]: a directory of rules and indicators that the engine loads as one unit. |
//! | [`attack`] | MITRE ATT&CK names for rule tags. |
//! | [`common`] | Names, entities, and stable identifiers that the detectors share. |
//!
//! # Example
//!
//! ```
//! use aegis_contracts::common::EntityKind;
//! use aegis_contracts::event::{Actor, Event, EventClass, EventSource, action, attr};
//! use aegis_detect::{DetectionEngine, EngineConfig, PackManifest, RulePack, SigmaRule};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let rule = SigmaRule::parse(
//!     r"
//! title: Honeytoken used
//! id: example-honeytoken
//! level: critical
//! tags:
//!   - attack.credential-access
//!   - attack.t1552
//! detection:
//!   selection:
//!     action: honeytoken.trip
//!   condition: selection
//! ",
//!     "honeytoken.yml",
//! )?;
//! let manifest = PackManifest {
//!     name: "example".to_owned(),
//!     version: "1.0.0".to_owned(),
//!     description: "One rule.".to_owned(),
//! };
//! let pack = RulePack::new(manifest, vec![rule], Vec::new())?;
//! let engine = DetectionEngine::new(EngineConfig::default(), pack)?;
//!
//! let event = Event::new(
//!     chrono::DateTime::UNIX_EPOCH,
//!     EventSource::new("vault", "example", "vault").with_tenant("tenant-1"),
//!     EventClass::ApiActivity,
//!     action::HONEYTOKEN_TRIP,
//!     Actor::new(EntityKind::ServicePrincipal, "sp-1"),
//! )
//! .with_attribute(attr::HONEYTOKEN_ID, "honeytoken-1");
//!
//! let runtime = tokio::runtime::Builder::new_current_thread().build()?;
//! let output = runtime.block_on(engine.process(&event))?;
//! assert_eq!(output.detections.len(), 1);
//! assert_eq!(output.detections[0].rule_id, "example-honeytoken");
//! assert_eq!(output.incidents.len(), 1);
//! # Ok(())
//! # }
//! ```
//!
//! # Time
//!
//! All detectors and the correlator use the time of the events and not the clock of the
//! host. Detection and incident identifiers come from the rule and the events. A replay of
//! a recorded log thus gives the same detections and the same incidents as the live stream.

/// Compiles the examples of the README of the crate as documentation tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;

pub mod attack;
pub mod common;
pub mod correlate;
pub mod engine;
pub mod error;
mod files;
pub mod ioc;
pub mod llm;
pub mod pack;
pub mod sigma;
pub mod velocity;

pub use correlate::{Correlator, CorrelatorConfig};
pub use engine::{BusRunnerConfig, DetectionEngine, EngineConfig, EngineOutput, RunSummary};
pub use error::DetectError;
pub use ioc::{Indicator, IndicatorKind, IocStore};
pub use llm::{LlmTriage, LlmTriageConfig};
pub use pack::{PackManifest, RulePack};
pub use sigma::{SigmaDetector, SigmaRule};
pub use velocity::{
    CredentialAfterGrant, ImpossibleSpeed, PrivilegedSelfAssignment, SignInBurst, VelocityConfig,
};
