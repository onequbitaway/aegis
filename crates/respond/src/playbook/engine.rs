//! The playbook engine. It selects playbooks for an incident and runs them.

use std::path::Path;
use std::sync::Arc;

use aegis_contracts::action::{
    ActionDispatcher, ActionDisposition, ActionKind, ActionRequest, ActionStatus,
};
use aegis_contracts::common::{ActionId, EntityRef, EvidenceKind, EvidenceRef, IncidentId};
use aegis_contracts::incident::Incident;
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_contracts::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::template::{self, Scope};
use super::{Playbook, PlaybookError, PlaybookOrigin, Step};
use crate::names::{error_kind, truncate};
use crate::revert::REVERT_AFTER_PARAMETER;

/// The principal identifier of requests from a playbook that the operator wrote.
pub const PLAYBOOK_PRINCIPAL_ID: &str = "playbook-engine";
/// The principal identifier of requests from a response draft that a model wrote.
pub const DRAFT_PRINCIPAL_ID: &str = "response-draft";

const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_EVIDENCE_DETECTIONS: usize = 64;
const MAX_NOTE_LENGTH: usize = 120;

/// How the engine runs a playbook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    /// Each request has `dry_run` set. No connector changes the environment.
    DryRun,
    /// The connectors change the environment, if policy permits.
    Live,
}

/// The result of one request of a playbook run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepResult {
    /// The dispatcher handled the request.
    Dispatched(ActionDisposition),
    /// The engine could not make the request, or the dispatcher returned an error.
    Failed {
        /// The error text.
        error: String,
        /// The name of the error variant, for example `unavailable`.
        kind: String,
        /// `true` if a new attempt can succeed.
        retryable: bool,
    },
    /// The target selector of the step gave no target for this incident.
    Skipped {
        /// Why the step has no target.
        reason: String,
    },
    /// The engine stopped at an earlier failure and did not run this step.
    NotRun,
}

/// One line of a playbook run report: one request, or one step that made no request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepRun {
    /// The name of the step.
    pub step: String,
    /// The action type of the step.
    pub action: ActionKind,
    /// The target of the request, if the step has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<EntityRef>,
    /// The identifier of the request, if the engine sent one to the dispatcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<ActionId>,
    /// What occurred.
    pub result: StepResult,
}

impl StepRun {
    /// Returns `true` if the request failed: an error, or an outcome with the status
    /// [`ActionStatus::Failed`].
    #[must_use]
    pub fn failed(&self) -> bool {
        match &self.result {
            StepResult::Failed { .. } => true,
            StepResult::Dispatched(ActionDisposition::Executed(outcome)) => {
                outcome.status == ActionStatus::Failed
            }
            StepResult::Dispatched(_) | StepResult::Skipped { .. } | StepResult::NotRun => false,
        }
    }
}

/// The report of one playbook run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlaybookRun {
    /// The name of the playbook.
    pub playbook: String,
    /// The incident that the playbook ran for.
    pub incident_id: IncidentId,
    /// How the engine ran the playbook.
    pub mode: RunMode,
    /// The time at which the run started.
    pub started_at: DateTime<Utc>,
    /// The time at which the run ended.
    pub completed_at: DateTime<Utc>,
    /// The step at which the engine stopped, if a failure stopped the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    /// One line for each request, in order. A step with many targets has many lines.
    pub steps: Vec<StepRun>,
}

impl PlaybookRun {
    /// Returns `true` if the engine ran all steps.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.stopped_at.is_none()
    }

    /// Returns the number of requests that failed.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.steps.iter().filter(|step| step.failed()).count()
    }
}

/// The result of [`PlaybookEngine::load_dir`].
#[derive(Debug)]
#[must_use = "examine `rejected`: a playbook that is not loaded does not run"]
pub struct LoadReport {
    /// The names of the playbooks that the engine loaded, in file name order.
    pub loaded: Vec<String>,
    /// One error for each file that the engine rejected. Each error names the file.
    pub rejected: Vec<PlaybookError>,
}

/// Selects playbooks for an incident and runs them through the action dispatcher.
///
/// The engine only makes action requests. The dispatcher applies policy, approval, and the
/// audit log to each request.
///
/// # Requests
///
/// Each request has these fields:
///
/// - `requested_by`: `playbook:<name>`, or `draft:<name>` for a response draft.
/// - `incident_id`: the incident.
/// - `evidence`: a link to the incident, then a link to each detection of the incident
///   (the first 64).
/// - `parameters`: the parameters of the step. A step with `revert_after` also gives the
///   parameter `revert_after_seconds`.
///
/// The principal of a playbook request is [`PLAYBOOK_PRINCIPAL_ID`] with the type
/// [`PrincipalKind::System`]. The principal of a draft request is [`DRAFT_PRINCIPAL_ID`]
/// with the type [`PrincipalKind::Agent`]. Policy can thus give a model draft less
/// authority than a playbook of the operator.
///
/// # Template variables
///
/// The `reason` and each string in `parameters` can use these variables between `{{` and
/// `}}`: `playbook.name`, `incident.id`, `incident.title`, `incident.severity`,
/// `incident.status`, `incident.tenant`, `incident.techniques`, `target.id`, `target.kind`,
/// `target.name`, `target.tenant`, and `detection.<key>`. `detection.<key>` is the first
/// value of the attribute `<key>` in the detections of the incident. A variable with no
/// value makes the request fail before the engine sends it.
pub struct PlaybookEngine {
    dispatcher: Arc<dyn ActionDispatcher>,
    playbooks: Vec<Playbook>,
}

fn principal(origin: &PlaybookOrigin) -> Principal {
    match origin {
        PlaybookOrigin::Operator => {
            Principal::new(PLAYBOOK_PRINCIPAL_ID, PrincipalKind::System, &["playbook"])
        }
        PlaybookOrigin::ModelDraft { .. } => Principal::new(
            DRAFT_PRINCIPAL_ID,
            PrincipalKind::Agent,
            &["response-draft"],
        ),
    }
}

/// Returns the result of a request that the engine could not make.
fn invalid(error: String) -> StepResult {
    StepResult::Failed {
        error,
        kind: error_kind(&Error::InvalidInput(String::new())).to_owned(),
        retryable: false,
    }
}

fn requested_by(playbook: &Playbook) -> String {
    match playbook.origin {
        PlaybookOrigin::Operator => format!("playbook:{}", playbook.name),
        PlaybookOrigin::ModelDraft { .. } => format!("draft:{}", playbook.name),
    }
}

fn evidence(playbook: &Playbook, step: &Step, incident: &Incident) -> Vec<EvidenceRef> {
    let mut links = vec![
        EvidenceRef::new(EvidenceKind::Incident, incident.id)
            .with_note(format!("playbook {}, step {}", playbook.name, step.id)),
    ];
    links.extend(
        incident
            .detections
            .iter()
            .take(MAX_EVIDENCE_DETECTIONS)
            .map(|detection| {
                EvidenceRef::new(EvidenceKind::Detection, detection.id)
                    .with_note(truncate(&detection.rule_id, MAX_NOTE_LENGTH))
            }),
    );
    links
}

/// Makes the request of one step for one target.
fn build_request(
    playbook: &Playbook,
    step: &Step,
    incident: &Incident,
    target: &EntityRef,
    mode: RunMode,
) -> std::result::Result<ActionRequest, String> {
    let scope = Scope {
        playbook: &playbook.name,
        incident,
        target,
    };
    let reason = if step.literal {
        step.reason.clone()
    } else {
        template::render(&step.reason, &scope).map_err(|error| format!("reason: {error}"))?
    };
    let mut request = ActionRequest::new(
        step.action.clone(),
        target.clone(),
        requested_by(playbook),
        reason,
    );
    for (name, value) in &step.parameters {
        let value = if step.literal {
            value.clone()
        } else {
            template::render_value(value, &scope)
                .map_err(|error| format!("parameter {name}: {error}"))?
        };
        request.parameters.insert(name.clone(), value);
    }
    if let Some(seconds) = step.revert_after {
        request
            .parameters
            .insert(REVERT_AFTER_PARAMETER.to_owned(), seconds.into());
    }
    request.incident_id = Some(incident.id);
    request.evidence = evidence(playbook, step, incident);
    request.dry_run = mode == RunMode::DryRun;
    Ok(request)
}

impl PlaybookEngine {
    /// Makes an engine with no playbooks.
    #[must_use]
    pub fn new(dispatcher: Arc<dyn ActionDispatcher>) -> Self {
        Self {
            dispatcher,
            playbooks: Vec::new(),
        }
    }

    /// Adds one playbook.
    ///
    /// Returns [`Error::Config`] if a playbook has the same name, or if the playbook is a
    /// response draft. A response draft is for one incident only. Give it to
    /// [`run`](Self::run) directly.
    pub fn add(&mut self, playbook: Playbook) -> Result<()> {
        if playbook.origin != PlaybookOrigin::Operator {
            return Err(Error::Config(format!(
                "the response draft {} cannot be a standing playbook",
                playbook.name
            )));
        }
        if self
            .playbooks
            .iter()
            .any(|known| known.name == playbook.name)
        {
            return Err(Error::Config(format!(
                "a playbook with the name {} is already loaded",
                playbook.name
            )));
        }
        self.playbooks.push(playbook);
        Ok(())
    }

    /// Loads each `.yaml` and `.yml` file of a directory, in file name order.
    ///
    /// The engine does not load a file that fails validation. The report holds one error
    /// with the file name and the reason for each rejected file. Examine
    /// [`LoadReport::rejected`].
    ///
    /// # Errors
    ///
    /// Returns [`PlaybookError::Io`] if the engine cannot read the directory.
    pub async fn load_dir(
        &mut self,
        directory: impl AsRef<Path>,
    ) -> std::result::Result<LoadReport, PlaybookError> {
        let directory = directory.as_ref();
        let io_error = |file: &Path| {
            let file = file.display().to_string();
            move |source| PlaybookError::Io { file, source }
        };
        let mut entries = tokio::fs::read_dir(directory)
            .await
            .map_err(io_error(directory))?;
        let mut files = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(io_error(directory))? {
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
                });
            if !is_yaml {
                continue;
            }
            // A file that the engine cannot read stays in the list, so that the report
            // names it. Only a directory is not a candidate.
            let is_directory = tokio::fs::metadata(&path)
                .await
                .is_ok_and(|metadata| metadata.is_dir());
            if !is_directory {
                files.push(path);
            }
        }
        files.sort();

        let mut report = LoadReport {
            loaded: Vec::new(),
            rejected: Vec::new(),
        };
        for path in files {
            let file = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            match self.load_file(&path, &file).await {
                Ok(name) => report.loaded.push(name),
                Err(error) => {
                    tracing::error!(%error, "the playbook is rejected");
                    report.rejected.push(error);
                }
            }
        }
        Ok(report)
    }

    async fn load_file(
        &mut self,
        path: &Path,
        file: &str,
    ) -> std::result::Result<String, PlaybookError> {
        let invalid = |reason: String| PlaybookError::Invalid {
            file: file.to_owned(),
            reason,
        };
        let io_error = |source| PlaybookError::Io {
            file: file.to_owned(),
            source,
        };
        let size = tokio::fs::metadata(path).await.map_err(io_error)?.len();
        if size > MAX_FILE_BYTES {
            return Err(invalid(format!(
                "the file has {size} bytes; the limit is {MAX_FILE_BYTES}"
            )));
        }
        let text = tokio::fs::read_to_string(path).await.map_err(io_error)?;
        let playbook = Playbook::from_yaml(file, &text)?;
        let name = playbook.name.clone();
        self.add(playbook)
            .map_err(|error| invalid(error.to_string()))?;
        Ok(name)
    }

    /// Returns the playbooks of the engine, in the order in which they were added.
    #[must_use]
    pub fn playbooks(&self) -> &[Playbook] {
        &self.playbooks
    }

    /// Returns the playbook with this name.
    #[must_use]
    pub fn playbook(&self, name: &str) -> Option<&Playbook> {
        self.playbooks.iter().find(|playbook| playbook.name == name)
    }

    /// Returns the playbooks whose trigger matches the incident, in the order in which they
    /// were added.
    #[must_use]
    pub fn matching(&self, incident: &Incident) -> Vec<&Playbook> {
        self.playbooks
            .iter()
            .filter(|playbook| playbook.matches(incident))
            .collect()
    }

    /// Runs each playbook that matches the incident. Returns one report for each playbook.
    pub async fn run_matching(
        &self,
        incident: &Incident,
        mode: RunMode,
    ) -> Result<Vec<PlaybookRun>> {
        let mut runs = Vec::new();
        for playbook in self.matching(incident) {
            runs.push(self.run(playbook, incident, mode).await?);
        }
        Ok(runs)
    }

    /// Runs one playbook for one incident.
    ///
    /// The engine makes one request for each target of each step, in order, and sends each
    /// request through the dispatcher. With [`RunMode::DryRun`], each request has `dry_run`
    /// set.
    ///
    /// A request fails if the engine cannot fill a template, the dispatcher returns an
    /// error, or the outcome has the status [`ActionStatus::Failed`]. A step fails with no
    /// request if it has more targets than its `max_targets`. A failure stops the run,
    /// unless the step has `continue_on_error`. A denial and a pending approval are not
    /// failures.
    ///
    /// The engine does not examine the trigger. The caller selects the playbook.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if the playbook is a response draft for a different
    /// incident. All other failures are in the report.
    pub async fn run(
        &self,
        playbook: &Playbook,
        incident: &Incident,
        mode: RunMode,
    ) -> Result<PlaybookRun> {
        if let Some(bound) = playbook.trigger.incident_id
            && bound != incident.id
        {
            return Err(Error::InvalidInput(format!(
                "the response draft {} is for the incident {bound}, not for the incident {}",
                playbook.name, incident.id
            )));
        }
        let principal = principal(&playbook.origin);
        let started_at = Utc::now();
        let mut steps: Vec<StepRun> = Vec::new();
        let mut stopped_at: Option<String> = None;

        for step in &playbook.steps {
            let line = |target: Option<EntityRef>, request_id, result| StepRun {
                step: step.id.clone(),
                action: step.action.clone(),
                target,
                request_id,
                result,
            };
            if stopped_at.is_some() {
                steps.push(line(None, None, StepResult::NotRun));
                continue;
            }
            let targets = step.target.resolve(incident);
            if targets.is_empty() {
                steps.push(line(
                    None,
                    None,
                    StepResult::Skipped {
                        reason: "The incident has no entity that the target selector matches."
                            .to_owned(),
                    },
                ));
                continue;
            }
            if targets.len() > step.max_targets {
                let run = line(
                    None,
                    None,
                    invalid(format!(
                        "the step has {} targets; its limit (max_targets) is {}",
                        targets.len(),
                        step.max_targets
                    )),
                );
                if !step.continue_on_error {
                    stopped_at = Some(step.id.clone());
                }
                steps.push(run);
                continue;
            }
            for target in targets {
                if stopped_at.is_some() {
                    steps.push(line(Some(target), None, StepResult::NotRun));
                    continue;
                }
                let run = match build_request(playbook, step, incident, &target, mode) {
                    Ok(request) => {
                        let request_id = request.id;
                        let result = match self.dispatcher.dispatch(request, &principal).await {
                            Ok(disposition) => StepResult::Dispatched(disposition),
                            Err(error) => StepResult::Failed {
                                error: error.to_string(),
                                kind: error_kind(&error).to_owned(),
                                retryable: error.is_retryable(),
                            },
                        };
                        line(Some(target), Some(request_id), result)
                    }
                    Err(error) => line(Some(target), None, invalid(error)),
                };
                if run.failed() && !step.continue_on_error {
                    stopped_at = Some(step.id.clone());
                }
                steps.push(run);
            }
        }

        Ok(PlaybookRun {
            playbook: playbook.name.clone(),
            incident_id: incident.id,
            mode,
            started_at,
            completed_at: Utc::now(),
            stopped_at,
            steps,
        })
    }
}
