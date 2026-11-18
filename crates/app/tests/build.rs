//! The build of the application from a configuration, and the reload of its files.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use aegis_app::actions::DispatchResult;
use aegis_app::{APP_ACTOR, App};
use aegis_contracts::action::{ActionDisposition, ActionKind, ActionStatus};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_contracts::{AgentRole, Error};
use aegis_core::{Config, Module, ModuleSet};
use aegis_testkit::{ScriptedModel, StaticSource, fixtures};

use support::{Starter, replace_once, spray_events, with_modules};

async fn build_error(starter: &Starter, config: &Config) -> Error {
    match App::builder(config).base_dir(starter.path()).build().await {
        Ok(_) => panic!("the configuration must not build"),
        Err(error) => error,
    }
}

fn config_message(error: &Error) -> &str {
    match error {
        Error::Config(message) => message,
        other => panic!("expected a configuration error, found {other:?}"),
    }
}

#[tokio::test]
async fn the_starter_configuration_builds_each_subsystem() {
    let starter = Starter::new();
    let app = starter.app().await;

    assert_eq!(app.modules().iter().count(), 8);
    assert!(!app.has_model());
    assert_eq!(app.models().name(), "offline");
    assert!(app.dispatcher().dry_run());
    assert_eq!(app.action_registry().names(), ["honeytokens", "simulation"]);
    assert_eq!(
        app.playbooks().names(),
        [
            "block-password-spray-source",
            "contain-compromised-user",
            "contain-rogue-service-principal",
            "isolate-compromised-host",
            "respond-to-honeytoken-trip"
        ]
    );
    assert_eq!(app.engine().pack().manifest().name, "aegis-identity");
    assert_eq!(app.engine().pack().rules().len(), 9);
    let agents = app.agents().unwrap();
    assert_eq!(agents.roster().roles().count(), 7);
    assert!(agents.config().dry_run);
    assert!(app.sources().is_empty());
    assert_eq!(app.policy().rule(), "data.aegis.response.decision");
    assert_eq!(app.settings().storage.kind(), "memory");
    // The build starts no work and writes no audit record.
    assert_eq!(app.audit().read(1, 10).await.unwrap(), []);
    assert_eq!(app.incidents().list(None, 10).await.unwrap(), []);
    assert_eq!(app.activity().count(), 0);
    app.close().await;
}

#[tokio::test]
async fn a_missing_or_unknown_section_stops_the_build_and_is_named() {
    let starter = Starter::new();
    let text = starter.config_text();

    for section in ["bus", "storage", "audit", "policy", "detection"] {
        let header = format!("[{section}]");
        assert_eq!(text.matches(&header).count(), 1);
        // Give the keys of the section to a section with a different name.
        let config = Config::from_toml_str(&text.replace(&header, "[renamed]")).unwrap();
        let error = build_error(&starter, &config).await;
        let message = config_message(&error);
        assert!(
            message
                .starts_with("the configuration has sections that AEGIS does not know: renamed."),
            "{message}"
        );
        // With the unknown section permitted, the missing section is the problem.
        let error = match App::builder(&config)
            .base_dir(starter.path())
            .allow_section("renamed")
            .build()
            .await
        {
            Ok(_) => panic!("the configuration must not build"),
            Err(error) => error,
        };
        assert_eq!(
            config_message(&error),
            format!("the section `{section}` is missing")
        );
    }
}

#[tokio::test]
async fn a_file_that_is_not_valid_stops_the_build_and_names_its_section() {
    // A rule of the rule pack is not valid.
    let starter = Starter::new();
    std::fs::write(
        starter
            .path()
            .join("detections/aegis-identity/rules/broken.yml"),
        "title: Broken\ndetection: [not, a, map]\n",
    )
    .unwrap();
    let error = build_error(&starter, &starter.config()).await;
    let message = config_message(&error);
    assert!(
        message.starts_with("the section `detection` is not valid:")
            && message.contains("broken.yml"),
        "{message}"
    );

    // The policy does not compile.
    let starter = Starter::new();
    std::fs::write(
        starter.path().join("policies/default.rego"),
        "package aegis.response\n\ndecision := {\n",
    )
    .unwrap();
    let error = build_error(&starter, &starter.config()).await;
    let message = config_message(&error);
    assert!(
        message.starts_with("the section `policy` is not valid:")
            && message.contains("default.rego"),
        "{message}"
    );

    // A playbook is not valid.
    let starter = Starter::new();
    std::fs::write(
        starter.path().join("playbooks/broken.yaml"),
        "name: broken\nsteps: []\n",
    )
    .unwrap();
    let error = build_error(&starter, &starter.config()).await;
    let message = config_message(&error);
    assert!(
        message.starts_with("the section `response` is not valid: 1 of the playbooks in")
            && message.contains("broken.yaml"),
        "{message}"
    );

    // The rule pack directory does not exist.
    let starter = Starter::new();
    let config = starter
        .config_with(|text| replace_once(&text, "detections/aegis-identity", "detections/missing"));
    let error = build_error(&starter, &config).await;
    assert!(
        config_message(&error).starts_with("the section `detection` is not valid:"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_connector_setting_that_is_not_valid_names_its_section_and_shows_no_secret() {
    let starter = Starter::new();

    // A route names a connector that the configuration does not have.
    let config = starter.config_with(|text| {
        text + "\n[[response.routes]]\nkind = \"block_ip\"\nconnector = \"perimeter\"\n"
    });
    let error = build_error(&starter, &config).await;
    let message = config_message(&error);
    assert!(
        message.starts_with("the section `response` is not valid:")
            && message.contains("perimeter"),
        "{message}"
    );

    // A webhook endpoint without TLS on a host that is not the loopback host.
    let config = starter.config_with(|text| {
        text + "\n[response.webhook]\nsecret = \"hunter2-hunter2-hunter2-hunter2\"\n\n\
                [[response.webhook.endpoints]]\nkind = \"notify\"\n\
                url = \"http://hooks.example.com/aegis\"\n"
    });
    let error = build_error(&starter, &config).await;
    let message = config_message(&error);
    assert!(
        message.starts_with("the section `response` is not valid:"),
        "{message}"
    );
    assert!(!message.contains("hunter2"), "{message}");

    // A webhook secret that is too short. The message does not show it.
    let config = starter
        .config_with(|text| text + "\n[response.webhook]\nsecret = \"hunter2\"\nendpoints = []\n");
    let error = build_error(&starter, &config).await;
    let message = config_message(&error);
    assert!(
        message.starts_with("the section `response` is not valid:"),
        "{message}"
    );
    assert!(!message.contains("hunter2"), "{message}");

    // A model provider whose key variable is not set.
    let config = starter.config_with(|text| {
        text + "\n[model.providers.hosted]\nkind = \"anthropic\"\n\
                api_key_env = \"AEGIS_TEST_KEY_THAT_IS_NOT_SET\"\nchat_model = \"model\"\n\n\
                [model.routes]\ndefault = [{ provider = \"hosted\" }]\n"
    });
    let error = build_error(&starter, &config).await;
    let message = config_message(&error);
    assert!(
        message.starts_with("the section `model` is not valid:")
            && message.contains("AEGIS_TEST_KEY_THAT_IS_NOT_SET"),
        "{message}"
    );
}

#[tokio::test]
async fn one_process_writes_one_audit_file() {
    let starter = Starter::new();
    let first = starter.app().await;

    let error = build_error(&starter, &starter.config()).await;

    assert!(
        matches!(&error, Error::Unavailable(message) if message.starts_with("[audit] ")),
        "{error:?}"
    );
    assert!(error.is_retryable());
    // After the first application goes away, the file is free.
    drop(first);
    let second = starter.app().await;
    assert_eq!(second.audit().read(1, 10).await.unwrap(), []);
}

#[tokio::test]
async fn the_builder_adds_what_the_configuration_file_does_not_have() {
    let starter = Starter::new();
    std::fs::write(
        starter.path().join("events.jsonl"),
        aegis_app::starter::attack_log(),
    )
    .unwrap();
    let config = starter.config_with(|text| {
        text + "\n[[sources]]\ntype = \"file\"\nname = \"configured\"\npath = \"events.jsonl\"\n"
    });

    // The configured source, and one more source.
    let extra = Arc::new(StaticSource::new("extra", Vec::new()));
    let app = starter
        .build(&config, |builder| builder.source(extra.clone()))
        .await;
    assert_eq!(app.sources().names(), ["configured", "extra"]);
    drop(app);

    // Only the source of the builder, the monitoring modules, and a model of the caller.
    let model = Arc::new(ScriptedModel::new("scripted"));
    let app = starter
        .build(&config, |builder| {
            builder
                .without_configured_sources()
                .source(extra.clone())
                .modules(ModuleSet::monitoring_only())
                .model(model.clone())
        })
        .await;
    assert_eq!(app.sources().names(), ["extra"]);
    assert!(app.modules().contains(Module::Monitor));
    assert!(!app.modules().contains(Module::Responder));
    let roles: Vec<AgentRole> = app.agents().unwrap().roster().roles().cloned().collect();
    assert_eq!(roles, [AgentRole::Supervisor, AgentRole::Monitor]);
    assert!(app.has_model());
    assert_eq!(app.models().name(), "scripted");
    drop(app);

    // Two sources with one name are an error of the `sources` section.
    let twin = Arc::new(StaticSource::new("configured", Vec::new()));
    let error = match App::builder(&config)
        .base_dir(starter.path())
        .source(twin)
        .build()
        .await
    {
        Ok(_) => panic!("the configuration must not build"),
        Err(error) => error,
    };
    assert!(
        config_message(&error).starts_with("the section `sources` is not valid:"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_module_set_with_no_agent_gives_no_agent_runtime_and_keeps_the_incidents() {
    let starter = Starter::new();
    let config = starter.config_with(|text| with_modules(&text, &["ingest", "detection"]));
    let app = starter.build(&config, |builder| builder).await;
    assert!(app.agents().is_none());

    let report = app.replay(fixtures::artex_style_attack()).await.unwrap();

    // The bridge writes the incident to the store with no agent.
    assert_eq!(report.agents, None);
    assert_eq!(report.detections.len(), 8);
    assert_eq!(report.incidents.len(), 1);
    assert_eq!(report.incidents[0].detections.len(), 8);
    assert_eq!(report.actions, []);
    assert_eq!(report.playbook_runs, []);
    assert_eq!(
        app.incidents().list(None, 10).await.unwrap(),
        report.incidents
    );
}

#[tokio::test]
async fn without_the_simulation_connector_an_action_with_no_connector_fails_and_changes_nothing() {
    let starter = Starter::new();
    let config = starter.config_with(|text| {
        replace_once(
            &text,
            "playbooks = \"dry_run\"",
            "playbooks = \"off\"\nsimulate_missing_connectors = false",
        )
    });
    let app = starter.build(&config, |builder| builder).await;
    assert_eq!(app.action_registry().names(), ["honeytokens"]);

    let report = app.replay(spray_events()).await.unwrap();

    assert_eq!(report.actions.len(), 1);
    let action = &report.actions[0];
    assert_eq!(action.request.kind, ActionKind::BlockIp);
    assert!(
        matches!(&action.result, DispatchResult::Failed { kind, retryable: false, .. } if kind == "unsupported"),
        "{:?}",
        action.result
    );
    assert!(!report.changed_the_environment());
    assert_eq!(report.agents.unwrap().dispatch_failures, 1);
    assert!(report.audit.verification.valid);
}

#[tokio::test]
async fn reload_takes_new_files_and_writes_a_configuration_change_record() {
    let starter = Starter::new();
    let app = starter.app().await;
    let digest_before = app.policy().version().digest;
    assert_eq!(app.engine().pack().rules().len(), 9);

    // The operator adds a rule, changes the policy, and adds a playbook.
    let rules = starter.path().join("detections/aegis-identity/rules");
    let rule = std::fs::read_to_string(rules.join("mfa_request_denied.yml"))
        .unwrap()
        .replace(
            "6e2d8b4a-1f93-4c60-8d2e-9a7f3b5c0e47",
            "6e2d8b4a-1f93-4c60-8d2e-9a7f3b5c0e48",
        )
        .replace(
            "Multi-factor authentication request denied",
            "A second rule",
        );
    std::fs::write(rules.join("second_rule.yml"), rule).unwrap();
    let policy_file = starter.path().join("policies/default.rego");
    let policy = std::fs::read_to_string(&policy_file).unwrap();
    std::fs::write(
        &policy_file,
        replace_once(
            &policy,
            "always_gated := set()",
            "always_gated := {\"notify\"}",
        ),
    )
    .unwrap();
    let playbooks = starter.path().join("playbooks");
    let playbook = std::fs::read_to_string(playbooks.join("block-password-spray-source.yaml"))
        .unwrap()
        .replace("name: block-password-spray-source", "name: a-new-playbook");
    std::fs::write(playbooks.join("a-new-playbook.yaml"), playbook).unwrap();

    let report = app.reload().await.unwrap();

    assert_eq!(report.pack, "aegis-identity");
    assert_eq!(report.rules, 10);
    assert_ne!(report.policy_digest, digest_before);
    assert_eq!(report.playbooks.len(), 6);
    assert_eq!(report.playbooks[0], "a-new-playbook");
    assert_eq!(app.engine().pack().rules().len(), 10);
    assert_eq!(app.policy().version().digest, report.policy_digest);
    assert_eq!(app.playbooks().names(), report.playbooks);

    let records = app.audit().read(1, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, AuditKind::ConfigChange);
    assert_eq!(records[0].actor, APP_ACTOR);
    assert_eq!(records[0].payload["policy"]["digest"], report.policy_digest);
    assert_eq!(records[0].payload["rule_pack"]["rules"], 10);
    assert_eq!(records[0].payload["playbooks"][0], "a-new-playbook");

    // The new policy is in use: a dry run is permitted as before, and the new playbook
    // runs with the others.
    let replay = app.replay(spray_events()).await.unwrap();
    let ran: Vec<&str> = replay
        .playbook_runs
        .iter()
        .map(|run| run.playbook.as_str())
        .collect();
    assert_eq!(ran, ["a-new-playbook", "block-password-spray-source"]);
    assert!(
        replay
            .actions
            .iter()
            .all(|action| matches!(&action.result, DispatchResult::Disposition(ActionDisposition::Executed(outcome))
                if outcome.status == ActionStatus::Simulated))
    );
}

#[tokio::test]
async fn a_reload_with_a_broken_file_keeps_the_old_state_and_returns_the_error() {
    let starter = Starter::new();
    let app = starter.app().await;
    let digest = app.policy().version().digest;
    let playbooks = app.playbooks().names();
    let rules = starter.path().join("detections/aegis-identity/rules");
    let policy_file = starter.path().join("policies/default.rego");
    let good_policy = std::fs::read_to_string(&policy_file).unwrap();
    let new_playbook = starter.path().join("playbooks/new.yaml");
    let good_playbook = std::fs::read_to_string(
        starter
            .path()
            .join("playbooks/block-password-spray-source.yaml"),
    )
    .unwrap()
    .replace("name: block-password-spray-source", "name: new-playbook");
    let good_rule = std::fs::read_to_string(rules.join("mfa_request_denied.yml"))
        .unwrap()
        .replace(
            "6e2d8b4a-1f93-4c60-8d2e-9a7f3b5c0e47",
            "6e2d8b4a-1f93-4c60-8d2e-9a7f3b5c0e49",
        );

    // Each case has one broken file and two good new files. The good files must not
    // become active when the third file is broken.
    type Step<'a> = Box<dyn Fn() + 'a>;
    let cases: [(&str, Step<'_>, Step<'_>); 3] = [
        (
            "detection",
            Box::new(|| {
                std::fs::write(rules.join("new.yml"), "title: Broken\ndetection: 7\n").unwrap();
                std::fs::write(&new_playbook, &good_playbook).unwrap();
                std::fs::write(&policy_file, format!("{good_policy}\n# A change.\n")).unwrap();
            }),
            Box::new(|| std::fs::remove_file(rules.join("new.yml")).unwrap()),
        ),
        (
            "response",
            Box::new(|| {
                std::fs::write(rules.join("new.yml"), &good_rule).unwrap();
                std::fs::write(&new_playbook, "name: [broken\n").unwrap();
                std::fs::write(&policy_file, format!("{good_policy}\n# A change.\n")).unwrap();
            }),
            Box::new(|| std::fs::remove_file(rules.join("new.yml")).unwrap()),
        ),
        (
            "policy",
            Box::new(|| {
                std::fs::write(rules.join("new.yml"), &good_rule).unwrap();
                std::fs::write(&new_playbook, &good_playbook).unwrap();
                std::fs::write(&policy_file, "package aegis.response\n\ndecision := {\n").unwrap();
            }),
            Box::new(|| std::fs::remove_file(rules.join("new.yml")).unwrap()),
        ),
    ];
    for (section, break_it, clean_up) in &cases {
        break_it();

        let error = app.reload().await.unwrap_err();

        assert!(
            config_message(&error).starts_with(&format!("the section `{section}` is not valid:")),
            "{section}: {error:?}"
        );
        assert_eq!(app.engine().pack().rules().len(), 9, "{section}");
        assert_eq!(app.policy().version().digest, digest, "{section}");
        assert_eq!(app.playbooks().names(), playbooks, "{section}");
        assert_eq!(app.audit().read(1, 10).await.unwrap(), [], "{section}");
        clean_up();
        std::fs::remove_file(&new_playbook).unwrap();
        std::fs::write(&policy_file, &good_policy).unwrap();
    }

    // With the files correct again, the reload succeeds.
    let report = app.reload().await.unwrap();
    assert_eq!(report.rules, 9);
    assert_eq!(report.policy_digest, digest);
    assert_eq!(app.audit().read(1, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn reload_by_a_principal_needs_the_permission_to_manage_the_policy() {
    let starter = Starter::new();
    let app = starter.app().await;

    let analyst = Principal::new("bob@example.com", PrincipalKind::Human, &["analyst"]);
    let error = app.reload_by(&analyst).await.unwrap_err();
    assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
    assert_eq!(app.audit().read(1, 10).await.unwrap(), []);

    let admin = Principal::new("carol@example.com", PrincipalKind::Human, &["admin"]);
    let report = app.reload_by(&admin).await.unwrap();
    assert_eq!(report.rules, 9);
    let records = app.audit().read(1, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, AuditKind::ConfigChange);
    assert_eq!(records[0].actor, "carol@example.com");
}

#[tokio::test]
async fn a_local_session_does_not_touch_the_bus_and_the_audit_log_of_the_configuration() {
    let starter = Starter::new();
    // The configuration names a NATS server that does not exist.
    let config = starter.config_with(|text| {
        replace_once(
            &text,
            "kind = \"memory\"\n\n[storage]",
            "kind = \"nats\"\n\n[bus.nats]\nurls = [\"nats://127.0.0.1:1\"]\n\
             connect_timeout = \"1s\"\n\n[storage]",
        )
    });
    let error = build_error(&starter, &config).await;
    assert!(
        error.is_retryable() && error.to_string().contains("[bus]"),
        "{error:?}"
    );

    let session_audit = starter.path().join("session/audit.jsonl");
    let app = starter
        .build(&config, |builder| builder.local_session(&session_audit))
        .await;

    assert_eq!(app.audit_path(), Some(session_audit.as_path()));
    assert_eq!(app.settings().storage.kind(), "memory");
    let report = app.replay(spray_events()).await.unwrap();
    assert_eq!(report.detections.len(), 1);
    assert!(session_audit.is_file());
    // The audit log of the configuration has no record of the session.
    assert!(!starter.audit_file().exists());
}

#[tokio::test]
async fn a_forced_dry_run_changes_nothing_with_a_configuration_that_is_live() {
    let starter = Starter::new();
    let config = starter.config_with(|text| {
        let text = replace_once(
            &text,
            "# With `true`, the dispatcher makes each action a dry run. No connector changes anything.\ndry_run = true",
            "dry_run = false",
        );
        let text = replace_once(&text, "playbooks = \"dry_run\"", "playbooks = \"live\"");
        replace_once(
            &text,
            "# With `true`, each action that an agent proposes is a dry run.\ndry_run = true",
            "dry_run = false",
        )
    });
    let firewall = Arc::new(aegis_testkit::RecordingConnector::new(
        "firewall",
        vec![ActionKind::BlockIp],
    ));

    // Without the option, the configuration is live: the gated action waits for a person.
    let live = starter
        .build(&config, |builder| {
            builder.action_connector(firewall.clone())
        })
        .await;
    assert!(!live.dispatcher().dry_run());
    assert_eq!(live.action_registry().names(), ["firewall", "honeytokens"]);
    drop(live);

    let app = starter
        .build(&config, |builder| {
            builder.action_connector(firewall.clone()).force_dry_run()
        })
        .await;
    assert!(app.dispatcher().dry_run());
    assert!(app.agents().unwrap().config().dry_run);
    assert_eq!(
        app.action_registry().names(),
        ["firewall", "honeytokens", "simulation"]
    );

    let report = app.replay(spray_events()).await.unwrap();

    assert!(report.dry_run);
    assert_eq!(report.playbook_runs.len(), 1);
    assert_eq!(report.actions.len(), 3);
    for action in &report.actions {
        assert!(action.request.dry_run, "{:?}", action.request.kind);
        assert!(
            matches!(&action.result, DispatchResult::Disposition(ActionDisposition::Executed(outcome))
                if outcome.status == ActionStatus::Simulated),
            "{:?}",
            action.result
        );
    }
    assert!(!report.changed_the_environment());
    // The real connector got only dry runs.
    let seen = firewall.executed();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|request| request.dry_run));
}
