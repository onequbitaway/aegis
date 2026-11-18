//! The starter directory: a working configuration with the files that it needs.
//!
//! The crate embeds these files of the repository at compile time: the detection pack
//! (`detections/`), the policies (`policies/`), the sample playbooks (`playbooks/`), and
//! the recorded attack log (`fixtures/artex_style_attack.jsonl`). A binary that links this
//! crate can thus make a starter directory with no checkout of the repository.
//!
//! The starter configuration changes nothing in the environment of the operator: the
//! storage and the bus are in the memory of the process, each action is a dry run, and no
//! model is configured.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use aegis_contracts::event::Event;
use aegis_contracts::{Error, Result};

include!(concat!(env!("OUT_DIR"), "/embedded.rs"));

/// The name of the configuration file in the starter directory.
pub const CONFIG_FILE: &str = "aegis.toml";

/// The directory for the audit log and the checkpoints, below the starter directory.
pub const DATA_DIRECTORY: &str = "data";

/// The path of the audit log, below the starter directory.
pub const AUDIT_FILE: &str = "data/audit.jsonl";

/// The largest number of files that the error for existing files names.
const MAX_NAMED_FILES: usize = 3;

/// The text of the starter configuration file.
pub const CONFIG: &str = r#"# The AEGIS starter configuration.
#
# This configuration changes nothing in your environment:
#   - Each response action is a dry run.
#   - The storage and the message bus are in the memory of the process.
#   - No model is configured. The agents use their deterministic paths.
#
# A relative path starts at the directory of this file.
# An environment variable can set one key, for example:
#   AEGIS__TELEMETRY__LOG_LEVEL=debug

[modules]
# The subsystems that the process runs. Remove "responder" to only monitor.
enabled = ["ingest", "detection", "monitor", "hunter", "analyst", "responder", "deception", "reporter"]

[telemetry]
service_name = "aegis"
log_format = "text"
log_level = "warn"

[bus]
# "memory" needs no server. Use "nats" with a [bus.nats] table for NATS JetStream.
kind = "memory"

[storage]
# "memory" loses the data when the process stops. Use "postgres" with a `url` key for
# PostgreSQL.
kind = "memory"

[audit]
# The hash-chained audit log. One process writes one file.
kind = "file"
path = "data/audit.jsonl"

[policy]
# You own this policy. Change it to fit your environment.
paths = ["policies/default.rego"]

[rbac.roles]
analyst = ["view_incidents", "view_audit"]
approver = ["view_incidents", "approve_actions"]
admin = ["view_incidents", "view_audit", "manage_policy", "manage_connectors", "run_playbooks", "administer"]

[approval]
# The requester of an action cannot approve it, and only a person can decide.
four_eyes = true
humans_only = true

[detection]
pack = "detections/aegis-identity"

[agents]
goal = "Keep the environment of the operator safe."
# With `true`, each action that an agent proposes is a dry run.
dry_run = true
# The events that the Monitor agent writes to the Defensive Graph:
# "detected", "all", or "none".
monitor_events = "detected"

[response]
# With `true`, the dispatcher makes each action a dry run. No connector changes anything.
dry_run = true
# How the playbooks run: "off", "dry_run", or "live".
playbooks = "dry_run"
playbook_dir = "playbooks"

[ingest]
checkpoint_dir = "data/checkpoints"

# A source connector. This one reads normalized events from a JSON Lines file.
# [[sources]]
# type = "file"
# name = "replay"
# path = "events.jsonl"

# A model. Without this section, AEGIS uses no model.
# [model.providers.local]
# kind = "openai_compatible"
# base_url = "http://localhost:11434/v1"
# chat_model = "llama3.1:8b"
#
# [model.routes]
# default = [{ provider = "local" }]
"#;

/// Returns the recorded attack log as JSON Lines: one normalized event in each line.
#[must_use]
pub fn attack_log() -> &'static str {
    ATTACK_LOG
}

/// Returns the events of the recorded attack log, in time order.
///
/// # Errors
///
/// Returns [`Error::Serialization`] if the embedded log is not valid. This occurs only if
/// the file in the repository was not valid when the crate was compiled.
pub fn attack_events() -> Result<Vec<Event>> {
    events_from_jsonl(ATTACK_LOG)
}

/// Decodes events from JSON Lines text: one normalized event in each line.
///
/// Empty lines are ignored.
///
/// # Errors
///
/// Returns [`Error::Serialization`] with the line number, the column, and the type of the
/// problem if a line is not an event. The message has no text of the line.
pub fn events_from_jsonl(text: &str) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event = serde_json::from_str::<Event>(line).map_err(|error| {
            Error::Serialization(format!(
                "line {} is not a normalized event: {:?} problem at column {}",
                index + 1,
                error.classify(),
                error.column()
            ))
        })?;
        events.push(event);
    }
    Ok(events)
}

/// Returns the files of the starter directory: the path below the directory, and the
/// contents. The configuration file is the first item.
#[must_use]
pub fn files() -> Vec<(&'static str, &'static [u8])> {
    let mut files = Vec::with_capacity(STARTER_FILES.len() + 1);
    files.push((CONFIG_FILE, CONFIG.as_bytes()));
    files.extend(STARTER_FILES.iter().copied());
    files
}

/// Writes the starter directory to `directory`.
///
/// The function makes the directory if it does not exist. It writes the configuration
/// file, the detection pack, the policies, and the sample playbooks, and it makes the
/// data directory. It returns the paths of the files that it wrote.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] if one of the files exists already. The function then
/// writes no file. It never replaces a file. Returns [`Error::Other`] if the operating
/// system refuses a write.
pub fn write(directory: &Path) -> Result<Vec<PathBuf>> {
    let files = files();
    let existing: Vec<String> = files
        .iter()
        .map(|(name, _)| directory.join(name))
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .collect();
    if !existing.is_empty() {
        let shown = existing.len().min(MAX_NAMED_FILES);
        let mut names = existing[..shown].join(", ");
        if existing.len() > shown {
            names.push_str(&format!(", and {} more", existing.len() - shown));
        }
        return Err(Error::InvalidInput(format!(
            "the starter files exist already and AEGIS does not replace a file: {names}"
        )));
    }
    let failed = |path: &Path| {
        let operation = format!("write the starter file {}", path.display());
        move |error: std::io::Error| Error::other(operation, error)
    };
    let mut written = Vec::with_capacity(files.len());
    for (name, contents) in files {
        let path = directory.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(failed(&path))?;
        }
        // `create_new` refuses a file that a different program made after the check.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(failed(&path))?;
        file.write_all(contents).map_err(failed(&path))?;
        written.push(path);
    }
    let data = directory.join(DATA_DIRECTORY);
    fs::create_dir_all(&data).map_err(failed(&data))?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use aegis_core::Config;
    use aegis_testkit::fixtures;

    use super::*;
    use crate::settings::{PlaybookMode, Settings};

    #[test]
    fn the_embedded_attack_log_is_the_recorded_attack_log() {
        let events = attack_events().unwrap();
        assert_eq!(events.len(), fixtures::ATTACK_LOG_EVENTS);
        assert_eq!(events, fixtures::artex_style_attack());
    }

    #[test]
    fn a_line_that_is_not_an_event_gives_its_position_and_no_text_of_the_line() {
        let good = attack_log().lines().next().unwrap();
        let text = format!("{good}\n\n{{\"id\": \"secret-token-value\"}}\n");
        let error = events_from_jsonl(&text).unwrap_err();
        let Error::Serialization(message) = &error else {
            panic!("expected a serialization error, found {error:?}");
        };
        assert!(
            message.starts_with("line 3 is not a normalized event: Data problem at column "),
            "{message}"
        );
        assert!(!message.contains("secret-token-value"), "{message}");

        assert_eq!(events_from_jsonl("\n  \n").unwrap(), []);
    }

    #[test]
    fn write_makes_a_directory_that_the_settings_accept() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("starter");

        let written = write(&root).unwrap();

        assert_eq!(written.len(), files().len());
        assert_eq!(written[0], root.join(CONFIG_FILE));
        for path in &written {
            assert!(path.is_file(), "{}", path.display());
        }
        assert!(root.join("detections/aegis-identity/pack.yml").is_file());
        assert!(root.join("policies/default.rego").is_file());
        assert!(
            root.join("playbooks/contain-rogue-service-principal.yaml")
                .is_file()
        );
        assert!(root.join(DATA_DIRECTORY).is_dir());

        let config = Config::load(root.join(CONFIG_FILE)).unwrap();
        let settings = Settings::from_config(&config, &root, &[]).unwrap();
        assert!(settings.response.dry_run);
        assert!(settings.agents.runtime.dry_run);
        assert_eq!(settings.response.playbooks, PlaybookMode::DryRun);
        assert_eq!(settings.storage.kind(), "memory");
        assert!(settings.model.is_none());
        assert_eq!(
            settings.detection.pack,
            root.join("detections/aegis-identity")
        );
        assert_eq!(settings.agents.runtime.enabled_roles.len(), 7);
    }

    #[test]
    fn write_does_not_replace_a_file_and_writes_nothing_in_that_case() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policies/default.rego");
        fs::create_dir_all(policy.parent().unwrap()).unwrap();
        fs::write(&policy, "package mine\n").unwrap();

        let error = write(directory.path()).unwrap_err();

        let Error::InvalidInput(message) = &error else {
            panic!("expected an invalid input error, found {error:?}");
        };
        assert_eq!(
            *message,
            format!(
                "the starter files exist already and AEGIS does not replace a file: {}",
                policy.display()
            )
        );
        assert_eq!(fs::read_to_string(&policy).unwrap(), "package mine\n");
        assert!(!directory.path().join(CONFIG_FILE).exists());
        assert!(!directory.path().join("detections").exists());

        // A second write to a complete starter directory names the first files and
        // gives the number of the others.
        let second = tempfile::tempdir().unwrap();
        let written = write(second.path()).unwrap();
        let error = write(second.path()).unwrap_err();
        let Error::InvalidInput(message) = &error else {
            panic!("expected an invalid input error, found {error:?}");
        };
        assert!(
            message.contains(&second.path().join(CONFIG_FILE).display().to_string()),
            "{message}"
        );
        assert!(
            message.ends_with(&format!(", and {} more", written.len() - 3)),
            "{message}"
        );
    }
}
