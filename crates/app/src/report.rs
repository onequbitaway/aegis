//! The reports of the composition root.

use std::collections::BTreeSet;

use aegis_agents::RunReport;
use aegis_contracts::audit::ChainVerification;
use aegis_contracts::incident::Incident;
use aegis_contracts::policy::ApprovalRequest;
use aegis_contracts::{ActionDisposition, Detection};
use aegis_ingest::{IngestStats, RunOutcome};
use aegis_respond::PlaybookRun;
use serde::{Deserialize, Serialize};

use crate::actions::ActionRecord;
use crate::bridge::Progress;

/// The state of the audit log at the end of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSummary {
    /// The number of records in the log.
    pub records: u64,
    /// The result of the check of the full hash chain.
    pub verification: ChainVerification,
}

/// The result of [`App::replay`](crate::App::replay).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayReport {
    /// The number of events that the replay examined.
    pub events: u64,
    /// `true` if the global dry-run switch of the dispatcher was on.
    pub dry_run: bool,
    /// `true` if the configuration has a model.
    pub model: bool,
    /// The detections, in the order of the events.
    pub detections: Vec<Detection>,
    /// The incidents that the replay made or changed, in their last state from the store.
    pub incidents: Vec<Incident>,
    /// Each action request that went to the dispatcher, with its result.
    pub actions: Vec<ActionRecord>,
    /// The report of each playbook run.
    pub playbook_runs: Vec<PlaybookRun>,
    /// The counts of the agent runtime. `None` means that no agent is enabled.
    pub agents: Option<RunReport>,
    /// The state of the audit log.
    pub audit: AuditSummary,
}

impl ReplayReport {
    /// Returns the identifiers of the ATT&CK techniques of all detections.
    #[must_use]
    pub fn techniques(&self) -> BTreeSet<String> {
        self.detections
            .iter()
            .flat_map(|detection| &detection.attack)
            .map(|technique| technique.technique_id.clone())
            .collect()
    }

    /// Returns `true` if one action or more changed the environment of the operator.
    #[must_use]
    pub fn changed_the_environment(&self) -> bool {
        self.actions
            .iter()
            .any(|action| action.result.changed_the_environment())
    }
}

/// The result of [`App::decide_approval`](crate::App::decide_approval).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalOutcome {
    /// The approval request with the decision.
    pub approval: ApprovalRequest,
    /// What the dispatcher did with the approved action. `None` for a rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<ActionDisposition>,
}

/// The result of [`App::reload`](crate::App::reload).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadReport {
    /// The name of the active rule pack.
    pub pack: String,
    /// The version of the active rule pack.
    pub pack_version: String,
    /// The number of Sigma rules in the active rule pack.
    pub rules: usize,
    /// The number of indicators in the active rule pack.
    pub indicators: usize,
    /// The SHA-256 digest of the active policy.
    pub policy_digest: String,
    /// The names of the active playbooks.
    pub playbooks: Vec<String>,
}

/// What one ingestion runner did in a service run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSummary {
    /// The name of the connector.
    pub name: String,
    /// Why the runner stopped.
    pub outcome: RunOutcome,
    /// The counters of the runner.
    pub stats: IngestStats,
}

/// The result of [`App::run_with`](crate::App::run_with).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RunSummary {
    /// One line for each ingestion runner, in the order in which the runners stopped.
    pub sources: Vec<SourceSummary>,
    /// The counts of the bridges since the process started.
    pub progress: Progress,
    /// The counts of the agent runtime for this run. `None` means that no agent ran.
    pub agents: Option<RunReport>,
}
