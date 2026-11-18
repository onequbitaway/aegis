//! Helpers for the integration tests: a starter directory and an application from it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use aegis_app::{App, AppBuilder, starter};
use aegis_core::Config;
use tempfile::TempDir;

/// The time limit for a state that a test waits for.
pub const WAIT: Duration = Duration::from_secs(30);

/// A starter directory in a temporary directory.
pub struct Starter {
    directory: TempDir,
}

impl Starter {
    /// Writes the starter directory.
    pub fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        starter::write(directory.path()).unwrap();
        Self { directory }
    }

    /// Returns the path of the starter directory.
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Returns the path of the audit log file.
    pub fn audit_file(&self) -> PathBuf {
        self.path().join(starter::AUDIT_FILE)
    }

    /// Returns the text of the starter configuration.
    pub fn config_text(&self) -> String {
        std::fs::read_to_string(self.path().join(starter::CONFIG_FILE)).unwrap()
    }

    /// Reads the starter configuration after `change` changed its text.
    pub fn config_with(&self, change: impl FnOnce(String) -> String) -> Config {
        Config::from_toml_str(&change(self.config_text())).unwrap()
    }

    /// Reads the starter configuration.
    pub fn config(&self) -> Config {
        self.config_with(|text| text)
    }

    /// Builds the application from the starter configuration.
    pub async fn app(&self) -> App {
        self.build(&self.config(), |builder| builder).await
    }

    /// Builds the application from `config`, with the options that `options` sets.
    pub async fn build(
        &self,
        config: &Config,
        options: impl for<'a> FnOnce(AppBuilder<'a>) -> AppBuilder<'a>,
    ) -> App {
        options(App::builder(config).base_dir(self.path()))
            .build()
            .await
            .unwrap()
    }
}

/// Replaces `from` in `text` one time. The text must have `from` exactly one time.
pub fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert_eq!(
        text.matches(from).count(),
        1,
        "{from:?} in the configuration"
    );
    text.replace(from, to)
}

/// The configuration keys that make the actions real: no dry run of the dispatcher and
/// no dry run of the agents. The playbooks are off, so that only the agents propose.
pub fn live(text: &str) -> String {
    let text = replace_once(
        text,
        "[response]\n# With `true`, the dispatcher makes each action a dry run. No connector changes anything.\ndry_run = true",
        "[response]\ndry_run = false",
    );
    let text = replace_once(&text, "playbooks = \"dry_run\"", "playbooks = \"off\"");
    replace_once(
        &text,
        "# With `true`, each action that an agent proposes is a dry run.\ndry_run = true",
        "dry_run = false",
    )
}

/// Replaces the module list of the starter configuration.
pub fn with_modules(text: &str, modules: &[&str]) -> String {
    let list = modules
        .iter()
        .map(|module| format!("\"{module}\""))
        .collect::<Vec<_>>()
        .join(", ");
    replace_once(
        text,
        "enabled = [\"ingest\", \"detection\", \"monitor\", \"hunter\", \"analyst\", \"responder\", \"deception\", \"reporter\"]",
        &format!("enabled = [{list}]"),
    )
}

/// Returns the events of the attack log up to the end of the password spray. They give
/// one detection: the sign-in burst from the spray address.
pub fn spray_events() -> Vec<aegis_contracts::Event> {
    let end = aegis_testkit::fixtures::base_time() + chrono::Duration::seconds(631);
    aegis_testkit::fixtures::artex_style_attack()
        .into_iter()
        .filter(|event| event.time < end)
        .collect()
}

/// Returns the events of the attack log after the password spray, in time order.
pub fn events_after_the_spray() -> Vec<aegis_contracts::Event> {
    let end = aegis_testkit::fixtures::base_time() + chrono::Duration::seconds(631);
    aegis_testkit::fixtures::artex_style_attack()
        .into_iter()
        .filter(|event| event.time >= end)
        .collect()
}
