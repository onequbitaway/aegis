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
    let mut command = program(directory, arguments);
    if let Some(temp) = temp {
        command.env("TMPDIR", temp);
    }
    command.output().unwrap()
}

/// Makes the command for the program with `arguments`.
///
/// The program gets no `AEGIS__` variable and no API token of the test environment, and
/// its working directory is `directory`.
fn program(directory: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aegis"));
    for (name, _) in std::env::vars_os() {
        let name_text = name.to_string_lossy().to_uppercase();
        if name_text.starts_with("AEGIS__")
            || name_text == API_TOKEN_VARIABLE
            || DECOY_VARIABLES.contains(&name_text.as_str())
        {
            command.env_remove(name);
        }
    }
    command
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null());
    command
}

/// The variable that the `[api]` example of the starter configuration names.
const API_TOKEN_VARIABLE: &str = "AEGIS_TOKEN_ALICE";

/// The variables that the `[decoy]` example of the starter configuration names: the seed
/// and the decoy key.
const DECOY_VARIABLES: [&str; 2] = ["AEGIS_DECOY_SEED", "AEGIS_DECOY_MODEL_KEY"];

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
    assert!(report.contains("\nDetections (9)\n"), "{report}");
    let detections: Vec<&str> = report
        .lines()
        .filter(|line| line.contains("  malicious  "))
        .collect();
    assert_eq!(detections.len(), 9);
    for technique in [
        fixtures::expected::PASSWORD_SPRAY,
        fixtures::expected::CONSENT_GRANT,
        fixtures::expected::CREDENTIAL_ADD,
        fixtures::expected::ROLE_ASSIGN,
        fixtures::expected::CLOUD_ACCOUNT,
    ] {
        let lines: Vec<&str> = detections
            .iter()
            .copied()
            .filter(|line| line.contains(technique))
            .collect();
        assert!(!lines.is_empty(), "{technique} is not in a detection line");
    }
    // The chain of the workload identity at machine speed is one detection.
    let cadence: Vec<&str> = detections
        .iter()
        .copied()
        .filter(|line| line.ends_with("[aegis.velocity.machine_cadence]"))
        .collect();
    assert_eq!(cadence.len(), 1);
    assert!(cadence[0].contains("T1059.009"), "{}", cadence[0]);
    assert!(report.contains("Honeytoken used"), "{report}");
    // The incident.
    assert!(report.contains("\nIncidents (1)\n"), "{report}");
    let incident = report
        .lines()
        .find(|line| line.contains("Multi-stage attack"))
        .unwrap();
    assert!(incident.contains("critical"), "{incident}");
    assert!(incident.contains("investigating"), "{incident}");
    assert!(
        incident.ends_with("Multi-stage attack: 8 ATT&CK techniques in 9 detections"),
        "{incident}"
    );
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
    assert_eq!(records, 156);
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
    assert_eq!(detections.len(), 9);
    assert!(
        detections[0].contains("T1110.003")
            && detections[0].contains("Sign-in burst from one address"),
        "{}",
        detections[0]
    );
    assert!(
        detections[7].contains("T1059.009")
            && detections[7].contains("Chain of sensitive actions at machine speed"),
        "{}",
        detections[7]
    );
    assert!(
        detections[8].contains("T1552") && detections[8].contains("Honeytoken used"),
        "{}",
        detections[8]
    );
    let incidents: Vec<&str> = report
        .lines()
        .filter(|line| line.starts_with("INCIDENT   "))
        .collect();
    assert_eq!(incidents.len(), 7);
    assert!(incidents[6].contains("critical"), "{}", incidents[6]);
    assert!(
        report.ends_with(
            "\nMonitoring session complete: 648 events, 9 detections, 7 incident states. \
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
    assert_eq!(lines.len(), 17);
    let kinds: Vec<&str> = lines
        .iter()
        .map(|line| line["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.iter().filter(|kind| **kind == "detection").count(), 9);
    assert_eq!(kinds.iter().filter(|kind| **kind == "incident").count(), 7);
    assert_eq!(kinds[16], "summary");
    assert_eq!(lines[16]["actions"], 0);
    assert_eq!(lines[16]["events"], 648);
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
        9
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
    assert_eq!(report["detections"].as_array().unwrap().len(), 9);
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

/// Adds `api` to the module set of the starter configuration.
fn with_api_module(text: &str) -> String {
    assert_eq!(text.matches("\"reporter\"]").count(), 1);
    text.replace("\"reporter\"]", "\"reporter\", \"api\"]")
}

/// Removes the comment mark from the `[api]` example of the starter configuration, and
/// adds `api` to the module set.
#[cfg(feature = "api")]
fn with_api_example(text: &str) -> String {
    let (before, example) = text.split_once("# [api]\n").unwrap();
    let mut text = format!("{before}[api]\n");
    for line in example.lines() {
        let line = line
            .strip_prefix("# ")
            .or_else(|| line.strip_prefix('#'))
            .expect("each line of the example is a comment");
        text.push_str(line);
        text.push('\n');
    }
    with_api_module(&text)
}

#[cfg(feature = "api")]
#[test]
fn config_check_reports_each_problem_of_the_api_section_and_names_the_section() {
    let (directory, starter) = init();
    let config = starter.join("aegis.toml");
    let good = std::fs::read_to_string(&config).unwrap();
    let check = |arguments: &[&str]| {
        let mut all = vec!["config", "check", "--config", text(&config)];
        all.extend_from_slice(arguments);
        aegis(directory.path(), &all)
    };

    // A value that is out of range.
    std::fs::write(
        &config,
        format!("{good}\n[api]\nbind = \"127.0.0.1:8080\"\n\n[api.limits]\nmax_page_size = 5000\n"),
    )
    .unwrap();
    let problem = "configuration error: the section `api` is not valid: \
                   api.limits.max_page_size must be from 1 to 1000";
    let output = check(&[]);
    assert_failure(&output);
    assert_eq!(
        stdout(&output),
        format!(
            "The configuration {} has 1 problems:\n  1. {problem}\n",
            config.display()
        )
    );
    assert!(
        stderr(&output).contains("the section `api` is not valid:"),
        "{}",
        stderr(&output)
    );
    let json = check(&["--format", "json"]);
    assert_failure(&json);
    let value: Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(value["valid"], false);
    assert_eq!(value["problems"], serde_json::json!([problem]));
    // `run` fails in the same way and starts nothing.
    let run = aegis(directory.path(), &["run", "--config", text(&config)]);
    assert_failure(&run);
    assert_eq!(stdout(&run), "");
    assert!(
        stderr(&run).contains("the section `api` is not valid:"),
        "{}",
        stderr(&run)
    );
    assert!(!starter.join("data/audit.jsonl").exists());

    // A key that the section does not know.
    std::fs::write(&config, format!("{good}\n[api]\nopen = true\n")).unwrap();
    let output = check(&[]);
    assert_failure(&output);
    assert!(
        stdout(&output).contains("\n  1. configuration error: the section `api` is not valid:"),
        "{}",
        stdout(&output)
    );

    // The module `api` with no `[api]` section.
    std::fs::write(&config, with_api_module(&good)).unwrap();
    let output = check(&[]);
    assert_failure(&output);
    assert!(
        stdout(&output).contains("\n  1. configuration error: the section `api` is missing:"),
        "{}",
        stdout(&output)
    );

    // The example of the starter configuration, with no token in the environment. The
    // problem names the section and the variable.
    std::fs::write(&config, with_api_example(&good)).unwrap();
    let output = check(&[]);
    assert_failure(&output);
    assert_eq!(
        stdout(&output),
        format!(
            "The configuration {} has 1 problems:\n  1. configuration error: the section `api` \
             is not valid: principal alice@example.com: the environment variable \
             {API_TOKEN_VARIABLE} is not set\n",
            config.display()
        )
    );

    // With the token, the configuration is valid. The check shows the address.
    let token = "a-token-of-the-test-0123456789abcdef";
    let output = program(
        directory.path(),
        &[
            "config",
            "check",
            "--config",
            text(&config),
            "--format",
            "json",
        ],
    )
    .env(API_TOKEN_VARIABLE, token)
    .output()
    .unwrap();
    assert_success(&output);
    let value: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["summary"]["api"], "127.0.0.1:8080");
    assert!(!stdout(&output).contains(token) && !stderr(&output).contains(token));

    // The starter configuration starts no API.
    std::fs::write(&config, &good).unwrap();
    let json = check(&["--format", "json"]);
    assert_success(&json);
    let value: Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(value["summary"]["api"], "off");
}

#[cfg(not(feature = "api"))]
#[test]
fn a_build_without_the_api_feature_refuses_the_module_and_the_section() {
    let (directory, starter) = init();
    let config = starter.join("aegis.toml");
    let good = std::fs::read_to_string(&config).unwrap();

    // The module `api`.
    std::fs::write(&config, with_api_module(&good)).unwrap();
    let problem = "configuration error: the section `modules` is not valid: the module `api` \
                   needs the Cargo feature `api`, and this build does not have it.";
    let check = aegis(
        directory.path(),
        &["config", "check", "--config", text(&config)],
    );
    assert_failure(&check);
    assert!(
        stdout(&check).contains(&format!("\n  1. {problem}")),
        "{}",
        stdout(&check)
    );
    let run = aegis(directory.path(), &["run", "--config", text(&config)]);
    assert_failure(&run);
    assert_eq!(stdout(&run), "");
    assert!(
        stderr(&run).starts_with(&format!("error: {problem}")),
        "{}",
        stderr(&run)
    );

    // The `[api]` section.
    std::fs::write(
        &config,
        format!("{good}\n[api]\nbind = \"127.0.0.1:8080\"\n"),
    )
    .unwrap();
    let check = aegis(
        directory.path(),
        &["config", "check", "--config", text(&config)],
    );
    assert_failure(&check);
    assert!(
        stdout(&check).contains(
            "\n  1. configuration error: the section `api` is not valid: the section needs the \
             Cargo feature `api`, and this build does not have it"
        ),
        "{}",
        stdout(&check)
    );
}

/// Sends one GET request to the server at `address`. Returns the status and the body.
#[cfg(all(unix, feature = "api"))]
fn http_get(address: std::net::SocketAddr, path: &str, token: Option<&str>) -> (u16, String) {
    use std::io::{Read as _, Write as _};

    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n{authorization}\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}

/// The time limit for one step of a test that talks to the running program.
#[cfg(all(unix, feature = "api"))]
const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(all(unix, feature = "api"))]
#[test]
fn run_serves_the_operator_api_until_a_stop_signal() {
    use std::io::BufRead as _;
    use std::sync::mpsc;

    let (directory, starter) = init();
    let config = starter.join("aegis.toml");
    let good = std::fs::read_to_string(&config).unwrap();
    // The operating system selects the port. The log is JSON, so that the test can read
    // the address from it.
    let changed = with_api_example(&good)
        .replace("bind = \"127.0.0.1:8080\"", "bind = \"127.0.0.1:0\"")
        .replace("log_format = \"text\"", "log_format = \"json\"")
        .replace("log_level = \"warn\"", "log_level = \"info\"");
    assert!(changed.contains("bind = \"127.0.0.1:0\""));
    assert!(changed.contains("log_format = \"json\"") && changed.contains("log_level = \"info\""));
    std::fs::write(&config, changed).unwrap();
    let token = "a-token-of-the-test-0123456789abcdef";

    let mut child = program(
        directory.path(),
        &["run", "--config", text(&config), "--format", "json"],
    )
    .env(API_TOKEN_VARIABLE, token)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let process = child.id().to_string();
    let signal = |name: &str| {
        Command::new("kill")
            .args([name, &process])
            .status()
            .unwrap()
            .success()
    };

    // The first log record with an address is the address of the server.
    let log = std::io::BufReader::new(child.stderr.take().unwrap());
    let (lines, received) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in log.lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let address = loop {
        let line = match received.recv_timeout(LIMIT) {
            Ok(line) => line,
            Err(error) => {
                signal("-KILL");
                panic!("the program did not log the address of the API ({error}): {seen:?}");
            }
        };
        let address = serde_json::from_str::<Value>(&line)
            .ok()
            .and_then(|record| record["fields"]["address"].as_str().map(str::to_owned))
            .and_then(|address| address.parse::<std::net::SocketAddr>().ok());
        seen.push(line);
        if let Some(address) = address {
            break address;
        }
    };
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);

    // The server answers: the health route, the console, and the REST API with a token.
    let (status, body) = http_get(address, "/healthz", None);
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        serde_json::json!({ "status": "ok" })
    );
    let (status, page) = http_get(address, "/", None);
    assert_eq!(status, 200);
    assert!(page.starts_with("<!doctype html>"), "{page}");
    let (status, body) = http_get(address, "/api/v1/session", Some(token));
    assert_eq!(status, 200);
    let session: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(session["principal"]["id"], "alice@example.com");
    assert_eq!(
        session["permissions"],
        serde_json::json!(["view_incidents", "view_audit", "approve_actions"])
    );
    let (status, body) = http_get(address, "/api/v1/status", Some(token));
    assert_eq!(status, 200);
    let modules = serde_json::from_str::<Value>(&body).unwrap()["modules"].clone();
    assert!(
        modules
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("api")),
        "{modules}"
    );
    let (status, _) = http_get(address, "/api/v1/session", None);
    assert_eq!(status, 401);
    let (status, _) = http_get(
        address,
        "/api/v1/session",
        Some("not-the-token-0123456789abcdef012345"),
    );
    assert_eq!(status, 401);

    // The commands for timed reverts call the operator API of this running service. The
    // token comes from an environment variable.
    let url = format!("http://{address}");
    let reverts = |arguments: &[&str], token: Option<&str>| {
        let mut command = program(directory.path(), arguments);
        command
            .env_remove("AEGIS_API_TOKEN")
            .env_remove("AEGIS_API_URL");
        if let Some(token) = token {
            command.env("AEGIS_API_TOKEN", token);
        }
        command.output().unwrap()
    };
    let list = reverts(&["reverts", "list", "--url", &url], Some(token));
    assert_success(&list);
    assert_eq!(
        stdout(&list),
        format!(
            "Timed reverts (0) of the service at {url}\n  No action waits for a timed revert.\n"
        )
    );
    let list = reverts(
        &["reverts", "list", "--url", &url, "--format", "json"],
        Some(token),
    );
    assert_success(&list);
    assert_eq!(
        serde_json::from_str::<Value>(&stdout(&list)).unwrap(),
        serde_json::json!({ "enabled": true, "items": [], "total": 0 })
    );
    // The address can come from the environment, and the token variable has a name.
    let mut from_environment = program(
        directory.path(),
        &["reverts", "list", "--token-env", "AEGIS_TEST_OTHER_TOKEN"],
    );
    from_environment
        .env("AEGIS_API_URL", &url)
        .env("AEGIS_TEST_OTHER_TOKEN", token);
    let list = from_environment.output().unwrap();
    assert_success(&list);
    assert!(
        stdout(&list).starts_with("Timed reverts (0)"),
        "{}",
        stdout(&list)
    );

    // The service refuses a token that it does not know. The error does not show the token.
    let wrong = "not-the-token-0123456789abcdef012345";
    let refused = reverts(&["reverts", "list", "--url", &url], Some(wrong));
    assert_failure(&refused);
    assert!(
        stderr(&refused)
            .contains("the operator API answered GET /reverts with the status 401 (unauthorized)"),
        "{}",
        stderr(&refused)
    );
    assert!(!stderr(&refused).contains(wrong));
    // No token variable: the command sends no request.
    let no_token = reverts(&["reverts", "list", "--url", &url], None);
    assert_failure(&no_token);
    assert!(
        stderr(&no_token).contains("the environment variable AEGIS_API_TOKEN is not set"),
        "{}",
        stderr(&no_token)
    );
    // An action that has no pending revert, and an identifier that is not valid.
    let unknown = "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e";
    for arguments in [
        vec!["reverts", "confirm", unknown, "--url", &url],
        vec!["reverts", "extend", unknown, "--by", "2h", "--url", &url],
        vec!["reverts", "cancel", unknown, "--url", &url],
    ] {
        let output = reverts(&arguments, Some(token));
        assert_failure(&output);
        assert!(
            stderr(&output).contains("with the status 404 (not_found)"),
            "{arguments:?}: {}",
            stderr(&output)
        );
    }
    let bad = reverts(
        &["reverts", "confirm", "the-last-one", "--url", &url],
        Some(token),
    );
    assert_failure(&bad);
    assert!(
        stderr(&bad).contains("the action identifier is not a valid UUID"),
        "{}",
        stderr(&bad)
    );
    // The token never goes over the network with no encryption.
    let remote = reverts(
        &["reverts", "list", "--url", "http://192.0.2.10:8080"],
        Some(token),
    );
    assert_failure(&remote);
    assert!(
        stderr(&remote).contains("uses http for a host that is not a loopback address"),
        "{}",
        stderr(&remote)
    );

    // SIGTERM stops the server and the application. The exit status is 0.
    assert!(signal("-TERM"));
    let (done, exited) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        // The receiver is gone only if the test failed before.
        let _ = done.send(child.wait_with_output());
    });
    let output = match exited.recv_timeout(LIMIT) {
        Ok(output) => output.unwrap(),
        Err(error) => {
            signal("-KILL");
            panic!("the program did not stop after SIGTERM ({error})");
        }
    };
    waiter.join().unwrap();
    reader.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{:?}",
        received.try_iter().collect::<Vec<_>>()
    );
    let summary: Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(summary["progress"]["events_processed"], 0);
    assert_eq!(summary["sources"], serde_json::json!([]));
    // The server does not listen after the program stopped.
    let refused = std::net::TcpStream::connect(address).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    // The audit log of the run verifies.
    let verify = aegis(
        directory.path(),
        &[
            "audit",
            "verify",
            "--path",
            text(&starter.join("data/audit.jsonl")),
        ],
    );
    assert_success(&verify);
}

/// The `[share]` section of the tests. The recorded attack log uses the documentation
/// ranges, so the tests permit them. The office network is the network of the operator.
const SHARE_SECTION: &str = "\n[share]\noperator_networks = [\"198.51.100.0/24\"]\n\
                             permit_documentation_ranges = true\n";

/// The incident of the recorded attack log. Its identifier comes from its events.
const ATTACK_INCIDENT: &str = "508657f7-d921-8cb3-add4-c2bd62528abd";

/// Runs the demonstration in a new directory and returns its configuration file.
fn demo_directory() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("demo");
    let output = aegis(directory.path(), &["demo", "--dir", text(&target)]);
    assert_success(&output);
    assert!(
        stdout(&output).contains(&format!("\n  {ATTACK_INCIDENT}  critical")),
        "{}",
        stdout(&output)
    );
    let config = target.join("aegis.toml");
    (directory, config)
}

fn add_share_section(config: &Path) {
    let mut text = std::fs::read_to_string(config).unwrap();
    text.push_str(SHARE_SECTION);
    std::fs::write(config, text).unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

#[test]
fn report_abuse_writes_reports_whose_manifest_verifies_and_that_name_no_operator_data() {
    let (directory, config) = demo_directory();
    let out = directory.path().join("reports");
    let arguments = [
        "report",
        "abuse",
        "--config",
        text(&config),
        "--incident",
        ATTACK_INCIDENT,
        "--out",
        text(&out),
    ];

    // With no network of the operator, the command refuses and writes nothing.
    let refused = aegis(directory.path(), &arguments);
    assert_failure(&refused);
    assert!(
        stderr(&refused).contains("the section `share` has no `operator_networks`")
            && stderr(&refused).contains("AEGIS wrote no document"),
        "{}",
        stderr(&refused)
    );
    assert!(!out.exists());

    add_share_section(&config);
    let output = aegis(directory.path(), &arguments);
    assert_success(&output);
    let report = stdout(&output);
    assert!(
        report.starts_with(&format!(
            "Wrote 3 reports for the incident {ATTACK_INCIDENT} to {}:\n",
            out.display()
        )),
        "{report}"
    );
    // The command says which evidence it had, and that it sent nothing.
    for sentence in [
        "The incident comes from the evidence archive: the incident store of this \
         configuration is in the memory of the service.",
        "The evidence archive gave 9 detections and 18 log records. The archive holds only \
         the events that caused a detection, not all events of an address.",
        "The audit log has 156 records, and its hash chain verifies. 9 of them seal a \
         detection of this document.",
    ] {
        assert!(report.contains(sentence), "{sentence}\n{report}");
    }
    assert!(
        report.ends_with("\nAEGIS sent nothing. Read each document before you send it.\n"),
        "{report}"
    );

    // One directory for each attacker address, with the four files.
    let mut directories: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    directories.sort();
    assert_eq!(
        directories,
        [
            "address-192.0.2.77",
            "address-203.0.113.50",
            "address-203.0.113.51"
        ]
    );
    // The names of the operator that a report must not hold: the accounts, the
    // application, the tenant, and an address of the office network.
    let operator_names = [
        fixtures::VICTIM_USER_ID,
        fixtures::ROGUE_PRINCIPAL_ID,
        fixtures::ROGUE_APP_ID,
        fixtures::TENANT,
        "198.51.100.",
    ];
    // The evidence items of each report: the log records of the address that the archive
    // holds, and one audit record for each detection that names the address.
    let expected_items = [1 + 2, 13 + 4, 4 + 5];
    for (name, expected) in directories.iter().zip(expected_items) {
        let report_directory = out.join(name);
        let mut files: Vec<String> = std::fs::read_dir(&report_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        assert_eq!(
            files,
            [
                "evidence.jsonl",
                "manifest.json",
                "report.json",
                "report.md"
            ],
            "{name}"
        );

        // The manifest verifies: the hash of the file, and the hash of each line.
        let evidence = std::fs::read(report_directory.join("evidence.jsonl")).unwrap();
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(report_directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["algorithm"], "sha256", "{name}");
        assert_eq!(manifest["file_name"], "evidence.jsonl", "{name}");
        assert_eq!(manifest["file_bytes"], evidence.len(), "{name}");
        assert_eq!(manifest["file_sha256"], sha256_hex(&evidence), "{name}");
        let items = manifest["items"].as_array().unwrap();
        let lines: Vec<&[u8]> = evidence
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), expected, "{name}");
        assert_eq!(items.len(), lines.len(), "{name}");
        for (item, line) in items.iter().zip(&lines) {
            assert_eq!(item["sha256"], sha256_hex(line), "{name}: {item}");
        }

        for file in &files {
            let content = std::fs::read_to_string(report_directory.join(file)).unwrap();
            for operator_name in operator_names {
                assert!(
                    !content.contains(operator_name),
                    "{name}/{file} holds {operator_name}"
                );
            }
        }
        let address = name.strip_prefix("address-").unwrap();
        let markdown = std::fs::read_to_string(report_directory.join("report.md")).unwrap();
        assert!(
            markdown.starts_with(&format!("# Abuse report: activity from {address}\n")),
            "{markdown}"
        );
        assert!(
            markdown.contains("It does not identify a person or a group."),
            "{name}"
        );
    }

    // The command replaces no file.
    let before = std::fs::read(out.join("address-203.0.113.50/report.md")).unwrap();
    let again = aegis(directory.path(), &arguments);
    assert_failure(&again);
    assert!(
        stderr(&again).contains("exists already, and AEGIS does not replace a file"),
        "{}",
        stderr(&again)
    );
    assert_eq!(
        std::fs::read(out.join("address-203.0.113.50/report.md")).unwrap(),
        before
    );

    // An incident that the archive does not have, and an identifier that is not valid.
    let unknown = aegis(
        directory.path(),
        &[
            "report",
            "abuse",
            "--config",
            text(&config),
            "--incident",
            "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e",
            "--out",
            text(&directory.path().join("other")),
        ],
    );
    assert_failure(&unknown);
    assert!(
        stderr(&unknown).contains(
            "the incident 0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e was not found. The incident \
             store of this configuration is in the memory of the service"
        ),
        "{}",
        stderr(&unknown)
    );
    assert!(!directory.path().join("other").exists());
}

#[test]
fn indicators_export_writes_valid_stix_and_csv_and_needs_a_tlp_level() {
    let (directory, config) = demo_directory();
    let stix_file = directory.path().join("indicators.json");
    let export = |format: &str, tlp: Option<&str>, out: &Path| {
        let mut arguments = vec![
            "indicators",
            "export",
            "--config",
            text(&config),
            "--format",
            format,
            "--out",
            text(out),
        ];
        if let Some(tlp) = tlp {
            arguments.extend(["--tlp", tlp]);
        }
        aegis(directory.path(), &arguments)
    };

    // With no network of the operator, the command refuses.
    let refused = export("stix", Some("amber"), &stix_file);
    assert_failure(&refused);
    assert!(
        stderr(&refused).contains("the section `share` has no `operator_networks`"),
        "{}",
        stderr(&refused)
    );
    assert!(!stix_file.exists());
    add_share_section(&config);

    // The level has no default.
    let no_level = export("stix", None, &stix_file);
    assert_failure(&no_level);
    assert!(
        stderr(&no_level).contains("select the TLP level of the document with --tlp"),
        "{}",
        stderr(&no_level)
    );
    assert!(!stix_file.exists());

    let output = export("stix", Some("amber"), &stix_file);
    assert_success(&output);
    assert!(
        stdout(&output).starts_with(&format!(
            "Wrote 4 indicators to {} (format stix, TLP:AMBER).\n",
            stix_file.display()
        )),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).ends_with("\nAEGIS sent nothing. Read each document before you send it.\n")
    );

    // The file is one STIX 2.1 bundle: the TLP marking, and one indicator for each value.
    let bundle: Value = serde_json::from_slice(&std::fs::read(&stix_file).unwrap()).unwrap();
    assert_eq!(bundle["type"], "bundle");
    let bundle_id = bundle["id"].as_str().unwrap();
    assert!(is_stix_id(bundle_id, "bundle"), "{bundle_id}");
    let objects = bundle["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 5);
    let amber = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82";
    assert_eq!(objects[0]["type"], "marking-definition");
    assert_eq!(objects[0]["id"], amber);
    assert_eq!(
        objects[0]["definition"],
        serde_json::json!({ "tlp": "amber" })
    );
    let mut patterns = Vec::new();
    for object in &objects[1..] {
        assert_eq!(object["type"], "indicator", "{object}");
        assert_eq!(object["spec_version"], "2.1", "{object}");
        assert!(
            is_stix_id(object["id"].as_str().unwrap(), "indicator"),
            "{object}"
        );
        assert_eq!(object["pattern_type"], "stix", "{object}");
        assert_eq!(
            object["object_marking_refs"],
            serde_json::json!([amber]),
            "{object}"
        );
        assert_eq!(
            object["indicator_types"],
            serde_json::json!(["malicious-activity"]),
            "{object}"
        );
        for time in ["created", "modified", "valid_from", "valid_until"] {
            let value = object[time].as_str().unwrap();
            assert!(value.ends_with('Z') && value.len() == 24, "{time}: {value}");
        }
        patterns.push(object["pattern"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        patterns,
        [
            "[ipv4-addr:value = '192.0.2.77']",
            "[ipv4-addr:value = '203.0.113.50']",
            "[ipv4-addr:value = '203.0.113.51']",
            "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = \
             'python-httpx/0.27.0']",
        ]
    );
    // No object names an account, the tenant, or an address of the operator.
    let stix_text = std::fs::read_to_string(&stix_file).unwrap();
    for operator_name in [
        fixtures::VICTIM_USER_ID,
        fixtures::ROGUE_PRINCIPAL_ID,
        fixtures::TENANT,
        "198.51.100.",
    ] {
        assert!(!stix_text.contains(operator_name), "{operator_name}");
    }
    // The command replaces no file.
    let again = export("stix", Some("red"), &stix_file);
    assert_failure(&again);
    assert_eq!(std::fs::read_to_string(&stix_file).unwrap(), stix_text);

    // CSV: the header, and one row for each indicator with the level.
    let csv_file = directory.path().join("indicators.csv");
    assert_success(&export("csv", Some("green"), &csv_file));
    let csv = std::fs::read_to_string(&csv_file).unwrap();
    let rows: Vec<&str> = csv.split("\r\n").filter(|row| !row.is_empty()).collect();
    assert_eq!(rows.len(), 5, "{csv}");
    assert_eq!(
        rows[0],
        "type,value,basis,first_seen,last_seen,events,detections,techniques,tlp"
    );
    assert!(
        rows[2].starts_with("ipv4,203.0.113.50,malicious_activity,"),
        "{}",
        rows[2]
    );
    for row in &rows[1..] {
        assert!(row.ends_with(",TLP:GREEN"), "{row}");
    }

    // The recorded attack log has no decoy, so the format for a rule pack has no
    // indicator, and the command writes no file.
    let pack_file = directory.path().join("decoy.yml");
    let pack = export("pack", None, &pack_file);
    assert_failure(&pack);
    assert!(
        stderr(&pack).contains("The format pack uses only the detections of decoys"),
        "{}",
        stderr(&pack)
    );
    assert!(!pack_file.exists());

    // The document formats are not report formats of the other commands.
    let wrong = export("text", Some("amber"), &directory.path().join("x"));
    assert_failure(&wrong);
    assert!(
        stderr(&wrong).contains("--format stix, --format csv, or --format pack"),
        "{}",
        stderr(&wrong)
    );
    let demo = aegis(directory.path(), &["demo", "--format", "stix"]);
    assert_failure(&demo);
    assert!(
        stderr(&demo).contains("Use --format text or --format json with this command"),
        "{}",
        stderr(&demo)
    );
}

/// Returns `true` if `id` is a STIX identifier of the type `kind`: the type, two hyphens,
/// and a UUID.
fn is_stix_id(id: &str, kind: &str) -> bool {
    let Some(uuid) = id.strip_prefix(&format!("{kind}--")) else {
        return false;
    };
    let groups: Vec<&str> = uuid.split('-').collect();
    groups.iter().map(|group| group.len()).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
        && uuid
            .chars()
            .all(|character| character == '-' || character.is_ascii_hexdigit())
}

/// Removes the comment mark from the `[decoy]` example of the starter configuration.
fn with_decoy_example(text: &str) -> String {
    let (before, rest) = text.split_once("# [decoy]\n").unwrap();
    let mut example = String::from("[decoy]\n");
    let mut after = String::new();
    let mut in_example = true;
    for line in rest.lines() {
        if in_example {
            match line.strip_prefix("# ").or_else(|| line.strip_prefix('#')) {
                Some(line) => {
                    example.push_str(line);
                    example.push('\n');
                    continue;
                }
                // The first line that is not a comment ends the example.
                None => in_example = false,
            }
        }
        after.push_str(line);
        after.push('\n');
    }
    format!("{before}{example}{after}")
}

#[cfg(feature = "decoy")]
#[test]
fn config_check_validates_the_decoy_example_of_the_starter_configuration() {
    let (directory, starter) = init();
    let config = starter.join("aegis.toml");
    let good = std::fs::read_to_string(&config).unwrap();
    // The starter configuration has the example as a comment, so it starts no decoy.
    assert_eq!(good.matches("\n# [decoy]\n").count(), 1);
    let check = |contents: &str, variables: &[(&str, &str)]| {
        std::fs::write(&config, contents).unwrap();
        let mut command = program(
            directory.path(),
            &["config", "check", "--config", text(&config)],
        );
        command.envs(variables.iter().copied());
        command.output().unwrap()
    };
    let off = check(&good, &[]);
    assert_success(&off);
    assert!(
        stdout(&off).contains("\n  decoy: off\n"),
        "{}",
        stdout(&off)
    );

    // The example is a valid section. Its secrets come from the environment.
    let example = with_decoy_example(&good);
    assert!(example.contains("\n[decoy]\nid = \"decoy-lab\"\nbind = \"127.0.0.1:8081\"\n"));
    assert!(example.contains("\n[[decoy.model_api.keys]]\nid = \"ht-decoy-model-key\"\n"));
    let seed = "example-seed-0123456789abcdef0123456789";
    let key = "decoy-key-EXAMPLE-0123456789abcdefABCDEF";
    let valid = check(
        &example,
        &[("AEGIS_DECOY_SEED", seed), ("AEGIS_DECOY_MODEL_KEY", key)],
    );
    assert_success(&valid);
    assert!(
        stdout(&valid).contains("\n  decoy: 127.0.0.1:8081\n"),
        "{}",
        stdout(&valid)
    );
    // The check opened no listener: the address is free.
    drop(std::net::TcpListener::bind("127.0.0.1:8081"));

    // With no seed, the check names the variable. With a short seed, it does not show it.
    let no_seed = check(&example, &[("AEGIS_DECOY_MODEL_KEY", key)]);
    assert_failure(&no_seed);
    assert!(
        stdout(&no_seed).contains(
            "\n  1. configuration error: the section `decoy` is not valid: decoy decoy-lab: the \
             environment variable AEGIS_DECOY_SEED is not set\n"
        ),
        "{}",
        stdout(&no_seed)
    );
    let short = check(
        &example,
        &[
            ("AEGIS_DECOY_SEED", "short-seed"),
            ("AEGIS_DECOY_MODEL_KEY", key),
        ],
    );
    assert_failure(&short);
    assert!(
        stdout(&short).contains("the section `decoy` is not valid: decoy decoy-lab: the seed in"),
        "{}",
        stdout(&short)
    );
    assert!(!stdout(&short).contains("short-seed") && !stderr(&short).contains("short-seed"));

    // A value that is not valid, and a decoy on the address of the operator API.
    let bad = check(
        &example.replace(
            "personas = [\"tarpit\", \"maze\", \"model_api\"]",
            "personas = []",
        ),
        &[("AEGIS_DECOY_SEED", seed), ("AEGIS_DECOY_MODEL_KEY", key)],
    );
    assert_failure(&bad);
    assert!(
        stdout(&bad).contains("configuration error: the section `decoy` is not valid:"),
        "{}",
        stdout(&bad)
    );
    #[cfg(feature = "api")]
    {
        let clash = with_api_example(&example)
            .replace("bind = \"127.0.0.1:8081\"", "bind = \"127.0.0.1:8080\"");
        let output = check(
            &clash,
            &[
                ("AEGIS_DECOY_SEED", seed),
                ("AEGIS_DECOY_MODEL_KEY", key),
                (API_TOKEN_VARIABLE, "a-token-of-the-test-0123456789abcdef"),
            ],
        );
        assert_failure(&output);
        assert!(
            stdout(&output).contains(
                "the section `decoy` is not valid: bind is 127.0.0.1:8080, which is the address \
                 of the operator API (api.bind = 127.0.0.1:8080)"
            ),
            "{}",
            stdout(&output)
        );
    }
}

#[cfg(not(feature = "decoy"))]
#[test]
fn a_build_without_the_decoy_feature_refuses_the_section() {
    let (directory, starter) = init();
    let config = starter.join("aegis.toml");
    let good = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, with_decoy_example(&good)).unwrap();
    let check = aegis(
        directory.path(),
        &["config", "check", "--config", text(&config)],
    );
    assert_failure(&check);
    assert!(
        stdout(&check).contains(
            "\n  1. configuration error: the section `decoy` is not valid: the section needs the \
             Cargo feature `decoy`, and this build does not have it"
        ),
        "{}",
        stdout(&check)
    );
}
