//! The playbooks of the operator: the active set, its reload, and its run rules.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use aegis_contracts::action::ActionDispatcher;
use aegis_contracts::common::IncidentId;
use aegis_contracts::{Error, Result};
use aegis_respond::{PlaybookEngine, RunMode};

use crate::settings::PlaybookMode;

/// The largest number of (incident, playbook) pairs that the set remembers.
const MAX_REMEMBERED_RUNS: usize = 50_000;

/// The playbooks of the operator.
///
/// The set holds the active [`PlaybookEngine`]. [`Playbooks::reload`] replaces it. The set
/// also remembers which playbook ran for which incident, so that one playbook runs one
/// time for one incident.
pub struct Playbooks {
    dispatcher: Arc<dyn ActionDispatcher>,
    directory: Option<PathBuf>,
    mode: PlaybookMode,
    active: RwLock<Arc<PlaybookEngine>>,
    ran: Mutex<HashSet<(IncidentId, String)>>,
}

impl Playbooks {
    /// Loads the playbooks of `directory`. With `None`, the set has no playbook.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the directory cannot be read, or if one file is not a
    /// valid playbook. The message names each rejected file.
    pub async fn load(
        dispatcher: Arc<dyn ActionDispatcher>,
        directory: Option<PathBuf>,
        mode: PlaybookMode,
    ) -> Result<Self> {
        let engine = Self::read(&dispatcher, directory.as_deref()).await?;
        Ok(Self {
            dispatcher,
            directory,
            mode,
            active: RwLock::new(Arc::new(engine)),
            ran: Mutex::default(),
        })
    }

    async fn read(
        dispatcher: &Arc<dyn ActionDispatcher>,
        directory: Option<&Path>,
    ) -> Result<PlaybookEngine> {
        let mut engine = PlaybookEngine::new(dispatcher.clone());
        let Some(directory) = directory else {
            return Ok(engine);
        };
        let report = engine.load_dir(directory).await.map_err(|error| {
            Error::Config(format!(
                "cannot load the playbooks in {}: {error}",
                directory.display()
            ))
        })?;
        if !report.rejected.is_empty() {
            let reasons: Vec<String> = report.rejected.iter().map(ToString::to_string).collect();
            return Err(Error::Config(format!(
                "{} of the playbooks in {} are not valid: {}",
                reasons.len(),
                directory.display(),
                reasons.join("; ")
            )));
        }
        Ok(engine)
    }

    /// Reads the playbook directory again and makes the result the active set.
    ///
    /// Returns the names of the playbooks in the new set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if one file is not valid. The active set then stays.
    pub async fn reload(&self) -> Result<Vec<String>> {
        let engine = self.prepare().await?;
        Ok(self.activate(engine))
    }

    /// Reads the playbook directory again and returns the new engine. Changes nothing.
    pub(crate) async fn prepare(&self) -> Result<PlaybookEngine> {
        Self::read(&self.dispatcher, self.directory.as_deref()).await
    }

    /// Makes `engine` the active set. Returns the names of its playbooks.
    pub(crate) fn activate(&self, engine: PlaybookEngine) -> Vec<String> {
        let names = names_of(&engine);
        *self.active.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(engine);
        names
    }

    /// Returns the active playbook engine.
    #[must_use]
    pub fn engine(&self) -> Arc<PlaybookEngine> {
        self.active
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Returns the names of the active playbooks, in file name order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        names_of(&self.engine())
    }

    /// Returns how the composition root runs the playbooks.
    #[must_use]
    pub fn mode(&self) -> PlaybookMode {
        self.mode
    }

    /// Returns the run mode of the playbook engine, or `None` if no playbook runs.
    #[must_use]
    pub fn run_mode(&self) -> Option<RunMode> {
        match self.mode {
            PlaybookMode::Off => None,
            PlaybookMode::DryRun => Some(RunMode::DryRun),
            PlaybookMode::Live => Some(RunMode::Live),
        }
    }

    /// Records that `playbook` runs for `incident`. Returns `false` if it ran before.
    pub(crate) fn claim(&self, incident: IncidentId, playbook: &str) -> bool {
        let mut ran = self.ran.lock().unwrap_or_else(PoisonError::into_inner);
        if ran.len() >= MAX_REMEMBERED_RUNS && !ran.contains(&(incident, playbook.to_owned())) {
            ran.clear();
        }
        ran.insert((incident, playbook.to_owned()))
    }

    /// Removes the records of an incident that is closed.
    pub(crate) fn forget(&self, incident: IncidentId) {
        self.ran
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(id, _)| *id != incident);
    }
}

fn names_of(engine: &PlaybookEngine) -> Vec<String> {
    engine
        .playbooks()
        .iter()
        .map(|playbook| playbook.name().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use aegis_testkit::{DispatchMode, RecordingDispatcher};

    use super::*;

    const BLOCK: &str = r#"
name: block-spray-source
description: Block the address that a password spray comes from.
trigger:
  min_severity: medium
  techniques_any: [T1110.003]
steps:
  - id: block-address
    action: block_ip
    target:
      each_entity: ip_address
    reason: "Incident {{incident.id}}: block the spray address {{target.id}}."
"#;

    fn dispatcher() -> Arc<dyn ActionDispatcher> {
        Arc::new(RecordingDispatcher::new(DispatchMode::Execute))
    }

    #[tokio::test]
    async fn a_set_with_no_directory_has_no_playbook() {
        let playbooks = Playbooks::load(dispatcher(), None, PlaybookMode::Off)
            .await
            .unwrap();
        assert_eq!(playbooks.names(), Vec::<String>::new());
        assert_eq!(playbooks.run_mode(), None);
        assert_eq!(playbooks.reload().await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn reload_takes_a_new_file_and_keeps_the_set_when_a_file_is_broken() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("block.yaml"), BLOCK).unwrap();
        let playbooks = Playbooks::load(
            dispatcher(),
            Some(directory.path().to_path_buf()),
            PlaybookMode::Live,
        )
        .await
        .unwrap();
        assert_eq!(playbooks.names(), ["block-spray-source"]);
        assert_eq!(playbooks.mode(), PlaybookMode::Live);
        assert_eq!(playbooks.run_mode(), Some(RunMode::Live));

        let second = BLOCK.replace("block-spray-source", "block-second-source");
        std::fs::write(directory.path().join("second.yaml"), second).unwrap();
        assert_eq!(
            playbooks.reload().await.unwrap(),
            ["block-spray-source", "block-second-source"]
        );

        std::fs::write(
            directory.path().join("third.yaml"),
            "name: [not, a, playbook",
        )
        .unwrap();
        let error = playbooks.reload().await.unwrap_err();
        let Error::Config(message) = &error else {
            panic!("expected a configuration error, found {error:?}");
        };
        assert!(
            message.starts_with("1 of the playbooks in ") && message.contains("third.yaml"),
            "{message}"
        );
        assert_eq!(
            playbooks.names(),
            ["block-spray-source", "block-second-source"]
        );
    }

    #[tokio::test]
    async fn a_directory_that_does_not_exist_is_a_configuration_error() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        let error = Playbooks::load(dispatcher(), Some(missing), PlaybookMode::DryRun)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&error, Error::Config(message) if message.starts_with("cannot load the playbooks in ")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn one_playbook_is_claimed_one_time_for_one_incident() {
        let playbooks = Playbooks::load(dispatcher(), None, PlaybookMode::DryRun)
            .await
            .unwrap();
        let first = IncidentId::new();
        let second = IncidentId::new();
        assert!(playbooks.claim(first, "block"));
        assert!(!playbooks.claim(first, "block"));
        assert!(playbooks.claim(first, "contain"));
        assert!(playbooks.claim(second, "block"));

        playbooks.forget(first);
        assert!(playbooks.claim(first, "block"));
        assert!(!playbooks.claim(second, "block"));
    }
}
