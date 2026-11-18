//! The module set: the subsystems that one AEGIS process runs.
//!
//! One binary holds all subsystems. The `[modules]` section of the configuration selects
//! the subsystems that a process starts:
//!
//! ```toml
//! [modules]
//! enabled = ["ingest", "detection", "monitor"]
//! ```
//!
//! # Rules
//!
//! A module set must obey these rules. A set that breaks a rule is an
//! [`Error::Config`] that names the rule.
//!
//! | Rule | Reason |
//! | --- | --- |
//! | [`RULE_NOT_EMPTY`] | A process with no module protects nothing, but looks healthy. |
//! | [`RULE_RESPONDER_NEEDS_DETECTION`] | A response action must come from a detection in the same process. |
//!
//! # Default
//!
//! With no `[modules]` section or no `enabled` key, the set is
//! [`ModuleSet::monitoring_only`]. The operator must enable each module that can change the
//! environment.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// The name of the rule that a module set must have one module or more.
pub const RULE_NOT_EMPTY: &str = "at-least-one-module";

/// The name of the rule that the `responder` module needs the `detection` module.
pub const RULE_RESPONDER_NEEDS_DETECTION: &str = "responder-requires-detection";

/// One subsystem that a process can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    /// The source connectors. They publish normalized events on the bus.
    Ingest,
    /// The detection tiers and the correlator.
    Detection,
    /// The Monitor agent.
    Monitor,
    /// The Hunter agent.
    Hunter,
    /// The Analyst agent.
    Analyst,
    /// The Responder agent and the action path.
    Responder,
    /// The Deception agent.
    Deception,
    /// The Reporter agent.
    Reporter,
    /// The operator API.
    Api,
}

impl Module {
    /// All modules, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::Ingest,
        Self::Detection,
        Self::Monitor,
        Self::Hunter,
        Self::Analyst,
        Self::Responder,
        Self::Deception,
        Self::Reporter,
        Self::Api,
    ];

    /// Returns the name of the module in the configuration, for example `ingest`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Detection => "detection",
            Self::Monitor => "monitor",
            Self::Hunter => "hunter",
            Self::Analyst => "analyst",
            Self::Responder => "responder",
            Self::Deception => "deception",
            Self::Reporter => "reporter",
            Self::Api => "api",
        }
    }
}

impl fmt::Display for Module {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl FromStr for Module {
    type Err = Error;

    /// Parses the name of a module, for example `ingest`. The name is case-sensitive.
    fn from_str(text: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|module| module.name() == text)
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|module| module.name()).collect();
                Error::InvalidInput(format!(
                    "`{text}` is not a module name; use one of: {}",
                    names.join(", ")
                ))
            })
    }
}

/// The `[modules]` section of the configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModulesSection {
    enabled: Option<Vec<Module>>,
}

/// The set of modules that a process runs.
///
/// A value of this type always obeys the rules in the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleSet {
    modules: BTreeSet<Module>,
}

impl ModuleSet {
    /// The name of the configuration section.
    pub const SECTION: &'static str = "modules";

    /// Makes a set from `modules`. A module that occurs two times counts one time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] with the name of the rule if the set breaks a rule.
    pub fn new(modules: impl IntoIterator<Item = Module>) -> Result<Self> {
        let modules: BTreeSet<Module> = modules.into_iter().collect();
        if modules.is_empty() {
            return Err(Error::Config(format!(
                "the module set breaks the rule `{RULE_NOT_EMPTY}`: enable one module or more"
            )));
        }
        if modules.contains(&Module::Responder) && !modules.contains(&Module::Detection) {
            return Err(Error::Config(format!(
                "the module set breaks the rule `{RULE_RESPONDER_NEEDS_DETECTION}`: enable \
                 `detection`, or remove `responder`"
            )));
        }
        Ok(Self { modules })
    }

    /// Returns the set of all modules.
    #[must_use]
    pub fn all() -> Self {
        Self {
            modules: Module::ALL.into_iter().collect(),
        }
    }

    /// Returns the set for a process that only monitors: `ingest`, `detection`, and
    /// `monitor`. This set cannot change the environment of the operator.
    #[must_use]
    pub fn monitoring_only() -> Self {
        Self {
            modules: BTreeSet::from([Module::Ingest, Module::Detection, Module::Monitor]),
        }
    }

    /// Reads the `[modules]` section.
    ///
    /// With no section or no `enabled` key, the result is [`ModuleSet::monitoring_only`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the section is not valid or the set breaks a rule.
    pub fn from_config(config: &Config) -> Result<Self> {
        let section: ModulesSection = config.section_or_default(Self::SECTION)?;
        match section.enabled {
            Some(modules) => Self::new(modules),
            None => Ok(Self::monitoring_only()),
        }
    }

    /// Returns `true` if the process runs `module`.
    #[must_use]
    pub fn contains(&self, module: Module) -> bool {
        self.modules.contains(&module)
    }

    /// Returns the modules in the set, in the declaration order of [`Module`]. The set has
    /// one module or more.
    pub fn iter(&self) -> impl Iterator<Item = Module> + '_ {
        self.modules.iter().copied()
    }
}

impl fmt::Display for ModuleSet {
    /// Writes the module names with `, ` between them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, module) in self.modules.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(module.name())?;
        }
        Ok(())
    }
}
