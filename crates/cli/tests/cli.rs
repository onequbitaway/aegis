//! Tests of the built `aegis` program.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use aegis_testkit::fixtures;
use serde_json::Value;
use tempfile::TempDir;

/// The recorded attack log in the repository.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artex_style_attack.jsonl")
}

/// Runs the program with `arguments` and collects its output.
///
/// The program gets no `AEGIS__` variable of the test environment, and its working
/// directory is `directory`.
fn aegis(directory: &Path, arguments: &[&str]) -> Output {
    aegis_with_temp(directory, arguments, None)
}

/// Runs the program as [`aegis`] does. With `temp`, the program makes its temporary
/// files in that directory, so that the test removes them.
fn aegis_with_temp(directory: &Path, arguments: &[&str], temp: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aegis"));
    if let Some(temp) = temp {
        command.env("TMPDIR", temp);
    }
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().to_uppercase().starts_with("AEGIS__") {
            command.env_remove(name);
        }
    }
    command
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

fn assert_failure(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout(output),
        stderr(output)
    );
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A starter directory that `aegis init` wrote.
fn init() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let starter = directory.path().join("starter");
    let output = aegis(directory.path(), &["init", "--dir", text(&starter)]);
    assert_success(&output);
    (directory, starter)
}

#[test]
fn demo_prints_the_incident_the_actions_and_a_valid_chain() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("demo");

    let output = aegis(directory.path(), &["demo", "--dir", text(&target)]);

    assert_success(&output);
    let report = stdout(&output);
    assert!(
        report.starts_with(
            "AEGIS demonstration: replay of the recorded attack log: 648 events, dry run, no model\n"
        ),
        "{report}"
    );
    // The detections with their ATT&CK identifiers.
    assert!(report.contains("\nDetections (8)\n"), "{report}");
    for technique in [
        fixtures::expected::PASSWORD_SPRAY,
        fixtures::expected::CONSENT_GRANT,
        fixtures::expected::CREDENTIAL_ADD,
        fixtures::expected::ROLE_ASSIGN,
        fixtures::expected::CLOUD_ACCOUNT,
    ] {
        let lines: Vec<&str> = report
            .lines()
            .filter(|line| line.contains("  malicious  ") && line.contains(technique))
            .collect();
        assert!(!lines.is_empty(), "{technique} is not in a detection line");
    }
    assert!(report.contains("Honeytoken used"), "{report}");
    // The incident.
    assert!(report.contains("\nIncidents (1)\n"), "{report}");
    let incident = report
        .lines()
        .find(|line| line.contains("Multi-stage attack"))
        .unwrap();
    assert!(incident.contains("critical"), "{incident}");
    assert!(incident.contains("investigating"), "{incident}");
    let entities = report
        .lines()
        .find(|line| line.trim_start().starts_with("Entities:"))
        .unwrap();
    for entity in [
        format!("ip_address {}", fixtures::SPRAY_IP),
        format!("user {}", fixtures::VICTIM_USER_ID),
        format!("service_principal {}", fixtures::ROGUE_PRINCIPAL_ID),
    ] {
        assert!(entities.contains(&entity), "{entity} is not in {entities}");
    }
    // The containment actions with their dispositions.
    assert!(report.contains("\nActions (23)\n"), "{report}");
    let actions: Vec<&str> = report
        .lines()
        .filter(|line| line.contains("executed: simulated (connector "))
        .collect();
    assert_eq!(actions.len(), 23);
    for (kind, target, requester) in [
        ("block_ip", "ip_address 203.0.113.50", "responder"),
        ("kill_session", "user user-dana", "responder"),
        (
            "disable_service_principal",
            "service_principal sp-sync-helper",
            "responder",
        ),
        (
            "revoke_credential",
            "service_principal sp-sync-helper",
            "playbook:contain-rogue-service-principal",
        ),
    ] {
        assert!(
            actions.iter().any(|line| {
                let fields: Vec<&str> =
                    line.split("  ").filter(|field| !field.is_empty()).collect();
                fields.len() == 4
                    && fields[0].trim() == kind
                    && fields[1].trim() == target
                    && fields[2].trim() == requester
            }),
            "no line for {kind} on {target} by {requester}"
        );
    }
    assert!(
        report.contains("\n  No action changed the environment.\n"),
        "{report}"
    );
    // The audit result: the record count and the chain.
    let audit = report.split("\nAudit log\n").nth(1).unwrap();
    let records: u64 = audit
        .lines()
        .find_map(|line| line.trim().strip_prefix("Records: "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(records > 100, "{records}");
    assert!(audit.contains("\n  Chain: valid\n"), "{audit}");
    let file = target.join("data/audit.jsonl");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap().lines().count() as u64,
        records
    );
    // The report is on the standard output stream. The log is not.
    assert!(
        !report.contains(" WARN ") && !report.contains(" INFO "),
        "{report}"
    );

    // The starter directory of the demonstration is a working directory.
    let check = aegis(
        directory.path(),
        &[
            "config",
            "check",
            "--config",
            text(&target.join("aegis.toml")),
        ],
    );
    assert_success(&check);
}

#[test]
fn demo_with_no_directory_uses_a_new_temporary_directory() {
    let directory = tempfile::tempdir().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let output = aegis_with_temp(
        directory.path(),
        &["demo", "--format", "json"],
        Some(temp.path()),
    );
    assert_success(&output);
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["events"], 648);
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["audit"]["verification"]["valid"], true);
    assert_eq!(report["incidents"].as_array().unwrap().len(), 1);
    // The working directory gets no file.
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    // The starter directory of the demonstration stays in the temporary directory, with
    // the audit log of the run.
    let made: Vec<PathBuf> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(made.len(), 1);
    assert!(
        made[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("aegis-demo-")
    );
    assert!(made[0].join("aegis.toml").is_file());
    assert_eq!(
        std::fs::read_to_string(made[0].join("data/audit.jsonl"))
            .unwrap()
            .lines()
            .count() as u64,
        report["audit"]["records"].as_u64().unwrap()
    );
}

#[test]
fn init_writes_a_directory_that_config_check_accepts_and_replaces_no_file() {
    let (directory, starter) = init();
    for file in [
        "aegis.toml",
        "detections/aegis-identity/pack.yml",
        "policies/default.rego",
        "playbooks/contain-rogue-service-principal.yaml",
    ] {
        assert!(starter.join(file).is_file(), "{file}");
    }

    // The check runs from a different working directory: the paths of the configuration
    // start at the directory of the configuration file.
    let elsewhere = tempfile::tempdir().unwrap();
    let check = aegis(
        elsewhere.path(),
        &[
            "config",
            "check",
            "--config",
            text(&starter.join("aegis.toml")),
        ],
    );
    assert_success(&check);
    let report = stdout(&check);
    assert!(
        report.starts_with(&format!(
            "The configuration {} is valid.\n",
            starter.join("aegis.toml").display()
        )),
        "{report}"
    );
    assert!(report.contains("\n  storage: memory\n"), "{report}");
    assert!(
        report.contains("\n  dispatcher_dry_run: true\n"),
        "{report}"
    );
    assert!(
        report.contains("\n  rule_pack: aegis-identity\n"),
        "{report}"
    );

    let json = aegis(
        elsewhere.path(),
        &[
            "config",
            "check",
            "--config",
            text(&starter.join("aegis.toml")),
            "--format",
            "json",
        ],
    );
    assert_success(&json);
    let value: Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["problems"], serde_json::json!([]));
    assert_eq!(value["summary"]["model"], false);

    // A second `init` replaces nothing and fails.
    let policy = starter.join("policies/default.rego");
    std::fs::write(&policy, "package mine\n").unwrap();
    let again = aegis(directory.path(), &["init", "--dir", text(&starter)]);
    assert_failure(&again);
    assert_eq!(stdout(&again), "");
    assert!(
        stderr(&again).starts_with(
            "error: invalid input: the starter files exist already and AEGIS does not replace a file:"
        ),
        "{}",
        stderr(&again)
    );
    assert_eq!(std::fs::read_to_string(&policy).unwrap(), "package mine\n");
}

#[test]
fn monitor_prints_each_detection_and_incident_and_takes_no_action() {
    let directory = tempfile::tempdir().unwrap();

    let output = aegis(directory.path(), &["monitor", "--events", text(&fixture())]);

    assert_success(&output);
    let report = stdout(&output);
    let detections: Vec<&str> = report
        .lines()
        .filter(|line| line.starts_with("DETECTION  "))
        .collect();
    assert_eq!(detections.len(), 8);
    assert!(
        detections[0].contains("T1110.003")
            && detections[0].contains("Sign-in burst from one address"),
        "{}",
        detections[0]
    );
    assert!(
        detections[7].contains("T1552") && detections[7].contains("Honeytoken used"),
        "{}",
        detections[7]
    );
    let incidents: Vec<&str> = report
        .lines()
        .filter(|line| line.starts_with("INCIDENT   "))
        .collect();
    assert_eq!(incidents.len(), 7);
    assert!(incidents[6].contains("critical"), "{}", incidents[6]);
    assert!(
        report.ends_with(
            "\nMonitoring session complete: 648 events, 8 detections, 7 incident states. \
             Actions taken: 0.\n"
        ),
        "{report}"
    );
    // The first detection comes before the first incident state.
    let first_detection = report.find("DETECTION  ").unwrap();
    let first_incident = report.find("INCIDENT   ").unwrap();
    assert!(first_detection < first_incident);
    // The session leaves no file in the working directory.
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);

    // With JSON, each line is one JSON value.
    let json = aegis(
        directory.path(),
        &["monitor", "--events", text(&fixture()), "--format", "json"],
    );
    assert_success(&json);
    let lines: Vec<Value> = stdout(&json)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 16);
    let kinds: Vec<&str> = lines
        .iter()
        .map(|line| line["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.iter().filter(|kind| **kind == "detection").count(), 8);
    assert_eq!(kinds.iter().filter(|kind| **kind == "incident").count(), 7);
    assert_eq!(kinds[15], "summary");
    assert_eq!(lines[15]["actions"], 0);
    assert_eq!(lines[15]["events"], 648);
}

#[test]
fn monitor_with_a_configuration_does_not_write_the_audit_log_of_that_configuration() {
    let (directory, starter) = init();
    let output = aegis(
        directory.path(),
        &[
            "monitor",
            "--events",
            text(&fixture()),
            "--config",
            text(&starter.join("aegis.toml")),
        ],
    );
    assert_success(&output);
    assert_eq!(
        stdout(&output)
            .lines()
            .filter(|line| line.starts_with("DETECTION  "))
            .count(),
        8
    );
    assert!(!starter.join("data/audit.jsonl").exists());
}

#[test]
fn replay_gives_json_that_parses_and_an_audit_log_that_verifies() {
    let (directory, starter) = init();
    let config = starter.join("aegis.toml");

    let output = aegis(
        directory.path(),
        &[
            "replay",
            "--config",
            text(&config),
            "--events",
            text(&fixture()),
            "--format",
            "json",
        ],
    );

    assert_success(&output);
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["events"], 648);
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["model"], false);
    assert_eq!(report["detections"].as_array().unwrap().len(), 8);
    let incidents = report["incidents"].as_array().unwrap();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0]["severity"], "critical");
    assert_eq!(incidents[0]["status"], "investigating");
    let actions = report["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 23);
    for action in actions {
        assert_eq!(action["request"]["dry_run"], true);
        assert_eq!(
            action["result"]["disposition"]["executed"]["status"],
            "simulated"
        );
    }
    assert_eq!(report["audit"]["verification"]["valid"], true);
    let records = report["audit"]["records"].as_u64().unwrap();

    // `audit verify` reads the file that the replay wrote.
    let audit_file = starter.join("data/audit.jsonl");
    let verify = aegis(
        directory.path(),
        &["audit", "verify", "--path", text(&audit_file)],
    );
    assert_success(&verify);
    assert_eq!(
        stdout(&verify),
        format!(
            "Audit log {}\n  Records checked: {records}\n  Chain: valid\n",
            audit_file.display()
        )
    );

    // `audit show` prints the newest records.
    let show = aegis(
        directory.path(),
        &["audit", "show", "--path", text(&audit_file), "--limit", "2"],
    );
    assert_success(&show);
    let shown = stdout(&show);
    let lines: Vec<&str> = shown.lines().collect();
    assert_eq!(
        lines[0],
        format!(
            "Audit log {}: the newest 2 of {records} records",
            audit_file.display()
        )
    );
    assert!(
        lines[1]
            .trim_start()
            .starts_with(&(records - 1).to_string()),
        "{}",
        lines[1]
    );
    assert!(
        lines[2].trim_start().starts_with(&records.to_string()),
        "{}",
        lines[2]
    );
    assert_eq!(lines[4], "  Chain: valid");
    let show_json = aegis(
        directory.path(),
        &[
            "audit",
            "show",
            "--path",
            text(&audit_file),
            "--limit",
            "3",
            "--format",
            "json",
        ],
    );
    assert_success(&show_json);
    let value: Value = serde_json::from_str(&stdout(&show_json)).unwrap();
    assert_eq!(value["total"], records);
    assert_eq!(value["records"].as_array().unwrap().len(), 3);
    assert_eq!(value["records"][2]["sequence"], records);
}

#[test]
fn audit_verify_fails_on_a_log_with_one_changed_byte() {
    let (directory, starter) = init();
    let replay = aegis(
        directory.path(),
        &[
            "replay",
            "--config",
            text(&starter.join("aegis.toml")),
            "--events",
            text(&fixture()),
        ],
    );
    assert_success(&replay);
    let audit_file = starter.join("data/audit.jsonl");
    let good = std::fs::read(&audit_file).unwrap();

    // Change one byte in the summary of the record with the sequence number 5.
    let lines: Vec<&[u8]> = good.split(|byte| *byte == b'\n').collect();
    let offset: usize = lines[..4].iter().map(|line| line.len() + 1).sum();
    let line = String::from_utf8(lines[4].to_vec()).unwrap();
    assert!(line.contains("\"sequence\":5,"), "{line}");
    let position = offset + line.find("\"summary\":\"").unwrap() + "\"summary\":\"".len();
    let mut changed = good.clone();
    assert_ne!(changed[position], b'x');
    changed[position] = b'x';
    assert_eq!(changed.len(), good.len());
    std::fs::write(&audit_file, &changed).unwrap();

    let verify = aegis(
        directory.path(),
        &["audit", "verify", "--path", text(&audit_file)],
    );

    assert_failure(&verify);
    let report = stdout(&verify);
    assert!(report.contains("\n  Chain: NOT VALID\n"), "{report}");
    assert!(
        report.contains("\n  First invalid sequence: 5\n"),
        "{report}"
    );
    assert!(report.contains("\n  Records checked: 4\n"), "{report}");
    let message = stderr(&verify);
    assert!(
        message.contains("is not valid: the first invalid sequence is 5:"),
        "{message}"
    );

    let json = aegis(
        directory.path(),
        &[
            "audit",
            "verify",
            "--path",
            text(&audit_file),
            "--format",
            "json",
        ],
    );
    assert_failure(&json);
    let value: Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(value["verification"]["valid"], false);
    assert_eq!(value["verification"]["first_invalid_sequence"], 5);

    // A log that the process cannot use stops a new run, with the cause.
    let again = aegis(
        directory.path(),
        &[
            "replay",
            "--config",
            text(&starter.join("aegis.toml")),
            "--events",
            text(&fixture()),
        ],
    );
    assert_failure(&again);
    assert_eq!(stdout(&again), "");
    assert!(stderr(&again).contains("[audit]"), "{}", stderr(&again));

    // A file that does not exist is an error with the path.
    let missing = aegis(
        directory.path(),
        &[
            "audit",
            "verify",
            "--path",
            text(&starter.join("data/none.jsonl")),
        ],
    );
    assert_failure(&missing);
    assert!(
        stderr(&missing).contains("none.jsonl"),
        "{}",
        stderr(&missing)
    );
}

#[test]
fn a_bad_configuration_exits_with_an_error_that_names_each_section() {
    let (directory, starter) = init();
    let config = starter.join("aegis.toml");
    let good = std::fs::read_to_string(&config).unwrap();
    assert_eq!(good.matches("playbooks = \"dry_run\"").count(), 1);
    assert_eq!(good.matches("[policy]").count(), 1);
    let bad = good
        .replace("playbooks = \"dry_run\"", "playbooks = \"sometimes\"")
        .replace("[policy]", "[policy]\nrules = 7");
    std::fs::write(&config, bad).unwrap();

    let check = aegis(
        directory.path(),
        &["config", "check", "--config", text(&config)],
    );

    assert_failure(&check);
    let report = stdout(&check);
    assert!(
        report.starts_with(&format!(
            "The configuration {} has 2 problems:\n",
            config.display()
        )),
        "{report}"
    );
    assert!(
        report.contains("\n  1. configuration error: the section `policy` is not valid:"),
        "{report}"
    );
    assert!(
        report.contains("\n  2. configuration error: the section `response` is not valid:"),
        "{report}"
    );
    let message = stderr(&check);
    assert!(
        message.starts_with("error: the configuration "),
        "{message}"
    );
    assert!(message.contains("the section `policy`"), "{message}");
    assert!(message.contains("the section `response`"), "{message}");

    // Each command that reads the configuration fails in the same way and starts nothing.
    for arguments in [
        vec!["run", "--config", text(&config)],
        vec![
            "replay",
            "--config",
            text(&config),
            "--events",
            text(&fixture()),
        ],
    ] {
        let output = aegis(directory.path(), &arguments);
        assert_failure(&output);
        assert_eq!(stdout(&output), "");
        assert!(
            stderr(&output).contains("the section `policy` is not valid:"),
            "{}",
            stderr(&output)
        );
    }
    assert!(!starter.join("data/audit.jsonl").exists());

    // A file that is not valid, with sections that are valid.
    std::fs::write(&config, &good).unwrap();
    std::fs::write(
        starter.join("policies/default.rego"),
        "package aegis.response\n\ndecision := {\n",
    )
    .unwrap();
    let check = aegis(
        directory.path(),
        &["config", "check", "--config", text(&config)],
    );
    assert_failure(&check);
    assert!(
        stdout(&check).contains("the section `policy` is not valid:")
            && stdout(&check).contains("default.rego"),
        "{}",
        stdout(&check)
    );

    // A configuration file that does not exist.
    let missing = aegis(
        directory.path(),
        &[
            "config",
            "check",
            "--config",
            text(&starter.join("none.toml")),
        ],
    );
    assert_failure(&missing);
    assert!(
        stderr(&missing).contains("none.toml"),
        "{}",
        stderr(&missing)
    );
}

#[test]
fn an_event_file_that_is_not_valid_fails_with_the_line_number() {
    let (directory, starter) = init();
    let events = directory.path().join("events.jsonl");
    let first = std::fs::read_to_string(fixture()).unwrap();
    let first = first.lines().next().unwrap();
    std::fs::write(&events, format!("{first}\nnot an event\n")).unwrap();

    let replay = aegis(
        directory.path(),
        &[
            "replay",
            "--config",
            text(&starter.join("aegis.toml")),
            "--events",
            text(&events),
        ],
    );
    assert_failure(&replay);
    assert_eq!(stdout(&replay), "");
    assert!(
        stderr(&replay).contains("line 2 is not a normalized event"),
        "{}",
        stderr(&replay)
    );

    let monitor = aegis(directory.path(), &["monitor", "--events", text(&events)]);
    assert_failure(&monitor);
    assert!(stderr(&monitor).contains("line 2"), "{}", stderr(&monitor));

    let missing = aegis(
        directory.path(),
        &[
            "monitor",
            "--events",
            text(&directory.path().join("none.jsonl")),
        ],
    );
    assert_failure(&missing);
    assert!(
        stderr(&missing).starts_with("error: cannot read the event file"),
        "{}",
        stderr(&missing)
    );
}

#[test]
fn a_forced_dry_run_and_a_separate_audit_file_are_options_of_replay() {
    let (directory, starter) = init();
    let config = starter.join("aegis.toml");
    let text_before = std::fs::read_to_string(&config).unwrap();
    // The configuration permits changes.
    let live = text_before
        .replace(
            "connector changes anything.\ndry_run = true",
            "connector changes anything.\ndry_run = false",
        )
        .replace(
            "an agent proposes is a dry run.\ndry_run = true",
            "an agent proposes is a dry run.\ndry_run = false",
        );
    assert_ne!(live, text_before);
    std::fs::write(&config, live).unwrap();
    let audit = directory.path().join("separate/audit.jsonl");

    let output = aegis(
        directory.path(),
        &[
            "replay",
            "--config",
            text(&config),
            "--events",
            text(&fixture()),
            "--dry-run",
            "--audit-file",
            "separate/audit.jsonl",
            "--format",
            "json",
        ],
    );

    assert_success(&output);
    let report: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(report["dry_run"], true);
    let actions = report["actions"].as_array().unwrap();
    assert!(actions.len() >= 20, "{}", actions.len());
    for action in actions {
        assert_eq!(action["request"]["dry_run"], true);
    }
    assert!(audit.is_file());
    assert!(!starter.join("data/audit.jsonl").exists());
}

#[test]
fn a_command_line_that_is_not_valid_exits_with_a_usage_error() {
    let directory = tempfile::tempdir().unwrap();
    let no_command = aegis(directory.path(), &[]);
    assert_eq!(no_command.status.code(), Some(2));
    let unknown = aegis(directory.path(), &["attack"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(
        stderr(&unknown).contains("unrecognized subcommand"),
        "{}",
        stderr(&unknown)
    );
    let no_config = aegis(directory.path(), &["run"]);
    assert_eq!(no_config.status.code(), Some(2));
    assert!(
        stderr(&no_config).contains("--config"),
        "{}",
        stderr(&no_config)
    );
}
