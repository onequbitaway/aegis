//! The supervisor and the six specialized agents.
//!
//! Each agent implements [`Agent`]. An agent reads the shared services of the
//! [`AgentContext`](aegis_contracts::AgentContext) and returns an
//! [`AgentOutput`](aegis_contracts::AgentOutput). An agent never changes the environment
//! of the operator. It can only propose an action.

use std::collections::BTreeSet;
use std::sync::Arc;

use aegis_contracts::{Agent, AgentRole};

use crate::config::{BUILT_IN_ROLES, RuntimeConfig};

mod analyst;
mod deception;
mod hunter;
mod monitor;
mod reporter;
mod responder;
mod supervisor;

pub use analyst::{Analyst, Assessment, AssessmentVerdict};
pub use deception::Deception;
pub use hunter::Hunter;
pub use monitor::Monitor;
pub use reporter::{REPORT_SUBJECT, ReportDocument, Reporter};
pub use responder::{Candidate, Responder, containment_candidates};
pub use supervisor::Supervisor;

/// The set of roles that can receive tasks.
///
/// An agent uses the roster to select the next agent for an incident. An agent makes no
/// task for a role that is not in the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster(BTreeSet<AgentRole>);

impl Roster {
    /// Makes a roster with `roles`.
    pub fn new(roles: impl IntoIterator<Item = AgentRole>) -> Self {
        Self(roles.into_iter().collect())
    }

    /// Makes a roster with the seven built-in roles.
    #[must_use]
    pub fn all() -> Self {
        Self::new(BUILT_IN_ROLES)
    }

    /// Returns `true` if `role` can receive tasks.
    #[must_use]
    pub fn has(&self, role: &AgentRole) -> bool {
        self.0.contains(role)
    }

    /// Returns the roles in the roster.
    pub fn roles(&self) -> impl Iterator<Item = &AgentRole> {
        self.0.iter()
    }
}

/// Makes the built-in agent for `role`. A custom role gives `None`.
#[must_use]
pub fn built_in(
    role: &AgentRole,
    config: &RuntimeConfig,
    roster: &Roster,
) -> Option<Arc<dyn Agent>> {
    let roster = roster.clone();
    let agent: Arc<dyn Agent> = match role {
        AgentRole::Supervisor => Arc::new(Supervisor::new(roster)),
        AgentRole::Monitor => Arc::new(Monitor::new(config.monitor.clone(), roster)),
        AgentRole::Hunter => Arc::new(Hunter::new(config.hunter.clone())),
        AgentRole::Analyst => Arc::new(Analyst::new(config.analyst.clone(), roster)),
        AgentRole::Responder => Arc::new(Responder::new(
            config.responder.clone(),
            roster,
            config.dry_run,
        )),
        AgentRole::Deception => Arc::new(Deception::new(config.deception.clone(), roster)),
        AgentRole::Reporter => Arc::new(Reporter::new()),
        AgentRole::Custom(_) => return None,
    };
    Some(agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_built_in_role_has_an_agent_with_that_role() {
        let config = RuntimeConfig::default();
        let roster = Roster::all();
        assert_eq!(roster.roles().count(), 7);
        for role in BUILT_IN_ROLES {
            let agent = built_in(&role, &config, &roster).unwrap();
            assert_eq!(agent.role(), role);
        }
        assert!(built_in(&AgentRole::Custom("x".to_owned()), &config, &roster).is_none());
    }

    #[test]
    fn the_roster_knows_its_roles() {
        let roster = Roster::new([AgentRole::Monitor, AgentRole::Analyst]);
        assert!(roster.has(&AgentRole::Monitor));
        assert!(!roster.has(&AgentRole::Responder));
    }
}
