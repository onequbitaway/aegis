//! Checks of a configuration that start nothing and connect to nothing.

use std::path::Path;
use std::sync::Arc;

use aegis_contracts::action::{ActionDispatcher, ActionDisposition, ActionRequest};
use aegis_contracts::policy::Principal;
use aegis_contracts::{Error, Result};
use aegis_core::Config;
use aegis_detect::{DetectionEngine, RulePack};
use aegis_ingest::SourceRegistry;
use aegis_policy::RegoPolicyEngine;
use async_trait::async_trait;

use crate::playbooks::Playbooks;
use crate::settings::{PlaybookMode, Settings, section_error};

/// A dispatcher for a playbook engine that only reads playbook files. It runs no action.
struct NoDispatcher;

#[async_trait]
impl ActionDispatcher for NoDispatcher {
    async fn dispatch(&self, request: ActionRequest, _: &Principal) -> Result<ActionDisposition> {
        Err(Error::Unsupported(format!(
            "the configuration check runs no action: {}",
            request.id
        )))
    }
}

/// Reads the configuration and the files that it names, and returns all problems.
///
/// The function reads each section, the rule pack, the policy, the playbooks, the model
/// settings, and the source settings. It does not stop at the first problem. It opens no
/// connection, and it writes no file.
///
/// An empty result means that these parts are valid. [`App::build`](crate::App::build)
/// then finds the problems that need a connection, for example a bus that does not answer.
///
/// # Errors
///
/// The function returns no error. Each problem is one item of the result. The message of
/// a problem names its section.
pub async fn preflight(config: &Config, base_dir: &Path, extra_sections: &[String]) -> Vec<Error> {
    let settings = match Settings::read(config, base_dir, extra_sections) {
        Ok(settings) => settings,
        Err(problems) => return problems,
    };
    let mut problems = Vec::new();

    let pack_dir = settings.detection.pack.clone();
    let engine_config = settings.detection.engine.clone();
    let detection = tokio::task::spawn_blocking(move || {
        let pack = RulePack::load(pack_dir)?;
        DetectionEngine::new(engine_config, pack).map(|_| ())
    })
    .await;
    match detection {
        Ok(Ok(())) => {}
        Ok(Err(error)) => problems.push(section_error("detection", error.into())),
        Err(error) => problems.push(Error::other("load the rule pack", error)),
    }

    let policy = settings.policy.clone();
    match tokio::task::spawn_blocking(move || RegoPolicyEngine::from_config(&policy).map(|_| ()))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => problems.push(section_error("policy", error)),
        Err(error) => problems.push(Error::other("load the policy", error)),
    }

    if let Err(error) = Playbooks::load(
        Arc::new(NoDispatcher),
        settings.response.playbook_dir.clone(),
        PlaybookMode::Off,
    )
    .await
    {
        problems.push(section_error("response", error));
    }

    if let Some(model) = &settings.model
        && let Err(error) = aegis_model::build_router(model, aegis_model::process_env)
    {
        problems.push(section_error("model", error));
    }

    if let Err(error) = SourceRegistry::from_configs(&settings.sources) {
        problems.push(section_error("sources", error));
    }
    problems
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::starter;

    fn messages(problems: &[Error]) -> Vec<String> {
        problems
            .iter()
            .map(|problem| match problem {
                Error::Config(message) => message.clone(),
                other => panic!("expected a configuration error, found {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn the_starter_directory_has_no_problem_and_the_check_writes_no_file() {
        let directory = tempfile::tempdir().unwrap();
        starter::write(directory.path()).unwrap();
        let config = Config::load(directory.path().join(starter::CONFIG_FILE)).unwrap();

        let problems = preflight(&config, directory.path(), &[]).await;

        assert_eq!(messages(&problems), Vec::<String>::new());
        // The check opened no audit log.
        assert!(!directory.path().join(starter::AUDIT_FILE).exists());
    }

    #[tokio::test]
    async fn each_file_that_is_not_valid_is_one_problem() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        starter::write(root).unwrap();
        std::fs::write(
            root.join("detections/aegis-identity/rules/broken.yml"),
            "title: Broken\ndetection: 7\n",
        )
        .unwrap();
        std::fs::write(
            root.join("policies/default.rego"),
            "package aegis.response\n\ndecision := {\n",
        )
        .unwrap();
        std::fs::write(root.join("playbooks/broken.yaml"), "name: [broken\n").unwrap();
        let text = std::fs::read_to_string(root.join(starter::CONFIG_FILE)).unwrap()
            + "\n[[sources]]\ntype = \"file\"\nname = \"not a valid name\"\npath = \"x.jsonl\"\n\n\
               [model.providers.hosted]\nkind = \"anthropic\"\n\
               api_key_env = \"AEGIS_TEST_KEY_THAT_IS_NOT_SET\"\nchat_model = \"model\"\n\n\
               [model.routes]\ndefault = [{ provider = \"hosted\" }]\n";
        let config = Config::from_toml_str(&text).unwrap();

        let problems = messages(&preflight(&config, root, &[]).await);

        assert_eq!(problems.len(), 5, "{problems:?}");
        for (problem, section) in
            problems
                .iter()
                .zip(["detection", "policy", "response", "model", "sources"])
        {
            assert!(
                problem.starts_with(&format!("the section `{section}` is not valid:")),
                "{problem}"
            );
        }
        assert!(problems[0].contains("broken.yml"), "{}", problems[0]);
        assert!(problems[1].contains("default.rego"), "{}", problems[1]);
        assert!(problems[2].contains("broken.yaml"), "{}", problems[2]);
        assert!(
            problems[3].contains("AEGIS_TEST_KEY_THAT_IS_NOT_SET"),
            "{}",
            problems[3]
        );
    }

    #[tokio::test]
    async fn a_section_that_is_not_valid_is_reported_before_the_files() {
        let directory = tempfile::tempdir().unwrap();
        starter::write(directory.path()).unwrap();
        let text = std::fs::read_to_string(directory.path().join(starter::CONFIG_FILE))
            .unwrap()
            .replace("playbooks = \"dry_run\"", "playbooks = \"sometimes\"")
            .replace("kind = \"file\"", "kind = \"paper\"");
        let config = Config::from_toml_str(&text).unwrap();

        let problems = messages(&preflight(&config, directory.path(), &[]).await);

        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems[0].starts_with("the section `audit` is not valid:"),
            "{}",
            problems[0]
        );
        assert!(
            problems[1].starts_with("the section `response` is not valid:"),
            "{}",
            problems[1]
        );
    }
}
