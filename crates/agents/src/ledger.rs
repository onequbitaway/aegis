//! The record of proposed actions and their results in the timeline of an incident.
//!
//! An agent that proposes an action adds a timeline entry with an evidence link of the
//! type `action`. The note of the link holds the state, the action type, and the target:
//! `proposed block_ip ip_address:203.0.113.50`. The agent adds a second entry when the
//! result arrives. [`tracked_actions`] reads these entries.
//!
//! The record is in the incident, so it stays correct after a restart of the runtime.

use aegis_contracts::action::{ActionKind, ActionStatus};
use aegis_contracts::common::{ActionId, EntityRef, EvidenceKind, EvidenceRef};
use aegis_contracts::graph::NodeId;
use aegis_contracts::incident::Incident;
use serde::{Deserialize, Serialize};

use crate::support::token;

/// The state of one proposed action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    /// The agent proposed the action. No result is known.
    Proposed,
    /// Policy requires approval. The action waits for a person.
    PendingApproval,
    /// Policy denied the action.
    Denied,
    /// The dispatcher or the connector could not do the action.
    Failed,
    /// The action was a dry run. Nothing changed.
    Simulated,
    /// The connector found that no change was necessary.
    Skipped,
    /// The connector changed the target.
    Succeeded,
}

impl ActionState {
    /// Returns the state for the result state of a connector.
    #[must_use]
    pub fn from_status(status: ActionStatus) -> Self {
        match status {
            ActionStatus::Succeeded => Self::Succeeded,
            ActionStatus::Failed => Self::Failed,
            ActionStatus::Simulated => Self::Simulated,
            ActionStatus::Skipped => Self::Skipped,
        }
    }

    /// Returns `true` if the action did its work in the environment.
    #[must_use]
    pub fn is_done(self) -> bool {
        matches!(self, Self::Succeeded | Self::Skipped)
    }

    /// Returns `true` if a result is known for the action.
    #[must_use]
    pub fn is_settled(self) -> bool {
        self != Self::Proposed
    }

    /// A result with a larger rank replaces a result with a smaller rank.
    fn rank(self) -> u8 {
        match self {
            Self::Proposed => 0,
            Self::PendingApproval => 1,
            Self::Denied | Self::Failed | Self::Simulated => 2,
            Self::Skipped | Self::Succeeded => 3,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
    }
}

/// One proposed action and its last known state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedAction {
    /// The identifier of the action request.
    pub action_id: String,
    /// The action type, for example `block_ip`.
    pub kind: String,
    /// The node identifier of the target, for example `ip_address:203.0.113.50`.
    pub target: String,
    /// The agent that proposed the action, for example `responder`.
    pub author: String,
    /// The last known state.
    pub state: ActionState,
}

impl TrackedAction {
    /// Returns `true` if this record is for the action `kind` on `target`.
    pub(crate) fn is_for(&self, kind: &ActionKind, target: &EntityRef) -> bool {
        self.kind == kind_token(kind) && self.target == NodeId::for_entity(target).0
    }
}

/// Returns the action type as one token with no space.
pub(crate) fn kind_token(kind: &ActionKind) -> String {
    match kind {
        ActionKind::Custom(name) => format!("custom:{}", name.replace(char::is_whitespace, "_")),
        built_in => token(built_in),
    }
}

/// Makes the evidence link that records `state` for an action.
pub(crate) fn marker(
    action_id: ActionId,
    state: ActionState,
    kind: &ActionKind,
    target: &EntityRef,
) -> EvidenceRef {
    EvidenceRef::new(EvidenceKind::Action, action_id).with_note(format!(
        "{} {} {}",
        token(&state),
        kind_token(kind),
        NodeId::for_entity(target)
    ))
}

/// Makes the evidence link that records a new state for a known action.
pub(crate) fn marker_for(tracked: &TrackedAction, state: ActionState) -> EvidenceRef {
    EvidenceRef::new(EvidenceKind::Action, &tracked.action_id).with_note(format!(
        "{} {} {}",
        token(&state),
        tracked.kind,
        tracked.target
    ))
}

/// Reads the proposed actions of an incident and their last known states.
///
/// The actions are in the order in which the timeline first names them. The result does
/// not depend on the order of the entries for one action.
#[must_use]
pub fn tracked_actions(incident: &Incident) -> Vec<TrackedAction> {
    let mut actions: Vec<TrackedAction> = Vec::new();
    for entry in &incident.timeline {
        for link in &entry.evidence {
            if link.kind != EvidenceKind::Action {
                continue;
            }
            let Some(note) = link.note.as_deref() else {
                continue;
            };
            let mut parts = note.splitn(3, ' ');
            let (Some(state), Some(kind), Some(target)) = (
                parts.next().and_then(ActionState::parse),
                parts.next(),
                parts.next(),
            ) else {
                continue;
            };
            match actions.iter_mut().find(|known| known.action_id == link.id) {
                Some(known) => {
                    if state == ActionState::Proposed {
                        known.author.clone_from(&entry.author);
                    }
                    if state.rank() >= known.state.rank() {
                        known.state = state;
                    }
                }
                None => actions.push(TrackedAction {
                    action_id: link.id.clone(),
                    kind: kind.to_owned(),
                    target: target.to_owned(),
                    author: entry.author.clone(),
                    state,
                }),
            }
        }
    }
    actions
}

/// Returns the tracked actions that `author` proposed.
pub(crate) fn tracked_by(incident: &Incident, author: &str) -> Vec<TrackedAction> {
    tracked_actions(incident)
        .into_iter()
        .filter(|action| action.author == author)
        .collect()
}

#[cfg(test)]
mod tests {
    use aegis_contracts::AgentRole;
    use aegis_contracts::common::EntityKind;

    use super::*;
    use crate::support::add_timeline;
    use crate::support::testing::{attack_incident, rogue, spray_ip};

    #[test]
    fn a_marker_holds_the_state_the_type_and_the_target() {
        let id = ActionId::new();
        let link = marker(id, ActionState::Proposed, &ActionKind::BlockIp, &spray_ip());
        assert_eq!(link.kind, EvidenceKind::Action);
        assert_eq!(link.id, id.to_string());
        assert_eq!(
            link.note.as_deref(),
            Some("proposed block_ip ip_address:203.0.113.50")
        );
    }

    #[test]
    fn the_ledger_reads_the_last_state_of_each_action() {
        let mut incident = attack_incident();
        let block = ActionId::new();
        let disable = ActionId::new();
        let responder = AgentRole::Responder;
        add_timeline(
            &mut incident,
            &responder,
            "Proposed.",
            vec![
                marker(
                    block,
                    ActionState::Proposed,
                    &ActionKind::BlockIp,
                    &spray_ip(),
                ),
                marker(
                    disable,
                    ActionState::Proposed,
                    &ActionKind::DisableServicePrincipal,
                    &rogue(),
                ),
            ],
        );
        let proposed = tracked_actions(&incident);
        assert_eq!(proposed.len(), 2);
        assert!(
            proposed
                .iter()
                .all(|action| action.state == ActionState::Proposed)
        );
        assert!(proposed[0].is_for(&ActionKind::BlockIp, &spray_ip()));
        assert!(!proposed[0].is_for(&ActionKind::BlockIp, &rogue()));
        assert!(!proposed[0].is_for(&ActionKind::KillSession, &spray_ip()));

        add_timeline(
            &mut incident,
            &responder,
            "Pending.",
            vec![marker_for(&proposed[0], ActionState::PendingApproval)],
        );
        add_timeline(
            &mut incident,
            &responder,
            "Done.",
            vec![marker_for(&proposed[0], ActionState::Succeeded)],
        );
        add_timeline(
            &mut incident,
            &responder,
            "Denied.",
            vec![marker_for(&proposed[1], ActionState::Denied)],
        );
        let settled = tracked_by(&incident, "responder");
        assert_eq!(
            settled,
            [
                TrackedAction {
                    action_id: block.to_string(),
                    kind: "block_ip".to_owned(),
                    target: "ip_address:203.0.113.50".to_owned(),
                    author: "responder".to_owned(),
                    state: ActionState::Succeeded,
                },
                TrackedAction {
                    action_id: disable.to_string(),
                    kind: "disable_service_principal".to_owned(),
                    target: "service_principal:sp-sync-helper".to_owned(),
                    author: "responder".to_owned(),
                    state: ActionState::Denied,
                },
            ]
        );
        assert!(tracked_by(&incident, "deception").is_empty());
    }

    #[test]
    fn the_state_does_not_depend_on_the_order_of_the_entries() {
        let mut incident = attack_incident();
        let id = ActionId::new();
        let kind = ActionKind::KillSession;
        let target = EntityRef::new(EntityKind::User, "user with space");
        for state in [
            ActionState::Succeeded,
            ActionState::PendingApproval,
            ActionState::Proposed,
        ] {
            add_timeline(
                &mut incident,
                &AgentRole::Responder,
                "Entry.",
                vec![marker(id, state, &kind, &target)],
            );
        }
        let actions = tracked_actions(&incident);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].state, ActionState::Succeeded);
        assert_eq!(actions[0].target, "user:user with space");
        assert!(actions[0].is_for(&kind, &target));
    }

    #[test]
    fn links_that_are_not_action_records_are_ignored() {
        let mut incident = attack_incident();
        add_timeline(
            &mut incident,
            &AgentRole::Analyst,
            "Other evidence.",
            vec![
                EvidenceRef::new(EvidenceKind::Action, "a-1"),
                EvidenceRef::new(EvidenceKind::Action, "a-2").with_note("because"),
                EvidenceRef::new(EvidenceKind::Action, "a-3").with_note("exploded block_ip x"),
                EvidenceRef::new(EvidenceKind::Detection, "d-1").with_note("proposed block_ip x"),
            ],
        );
        assert!(tracked_actions(&incident).is_empty());
    }

    #[test]
    fn states_map_from_connector_results() {
        assert_eq!(
            ActionState::from_status(ActionStatus::Simulated),
            ActionState::Simulated
        );
        assert!(ActionState::from_status(ActionStatus::Succeeded).is_done());
        assert!(ActionState::from_status(ActionStatus::Skipped).is_done());
        assert!(!ActionState::from_status(ActionStatus::Failed).is_done());
        assert!(!ActionState::Simulated.is_done());
        assert!(ActionState::Denied.is_settled());
        assert!(!ActionState::Proposed.is_settled());
        assert_eq!(
            kind_token(&ActionKind::Custom("quarantine mail".to_owned())),
            "custom:quarantine_mail"
        );
    }
}
