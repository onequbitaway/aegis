//! Tests that need a process of their own.
//!
//! A test cannot change the environment of its own process safely, and it cannot read the
//! standard error stream of its own process. This program has no test harness. It starts
//! itself again as a child process. The child does one operation. The parent checks what the
//! child writes.
//!
//! - `Config::load_with_env` reads the environment of the process.
//! - `telemetry::init` writes the log lines to the standard error stream.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use aegis_core::Config;
use aegis_core::telemetry::{self, LogFormat, TelemetryConfig};
use serde::Deserialize;

/// The variable that tells the child process to load the configuration file at this path.
const CHILD_CONFIG: &str = "AEGIS_CORE_TEST_CHILD_CONFIG";

/// The variable that tells the child process to log with this format.
const CHILD_LOG_FORMAT: &str = "AEGIS_CORE_TEST_CHILD_LOG_FORMAT";

const DOCUMENT: &str = "[ingest]\nname = \"from-file\"\nbatch_size = 100\nenabled = false\n";

#[derive(Debug, Deserialize)]
struct Ingest {
    name: String,
    batch_size: u32,
    enabled: bool,
}

fn main() {
    if let Some(path) = std::env::var_os(CHILD_CONFIG) {
        config_child(Path::new(&path));
    } else if let Some(format) = std::env::var_os(CHILD_LOG_FORMAT) {
        telemetry_child(&format);
    } else {
        load_with_env_reads_the_environment_of_the_process();
        init_writes_the_log_lines_to_the_standard_error_stream();
        println!("child_process: all checks passed");
    }
}

/// Loads the configuration with the environment of this process and prints the result.
fn config_child(path: &Path) {
    let result = Config::load_with_env(path).and_then(|config| config.section::<Ingest>("ingest"));
    match result {
        Ok(ingest) => println!(
            "ok name={} batch_size={} enabled={}",
            ingest.name, ingest.batch_size, ingest.enabled
        ),
        Err(error) => println!("error {error}"),
    }
}

/// Installs the subscriber with `telemetry::init` and emits one event at two levels.
fn telemetry_child(format: &OsStr) {
    let log_format = match format.to_str() {
        Some("text") => LogFormat::Text,
        Some("json") => LogFormat::Json,
        other => panic!("unknown log format {other:?}"),
    };
    let config = TelemetryConfig {
        log_format,
        ..TelemetryConfig::default()
    };
    let guard = telemetry::init(&config).unwrap();
    tracing::debug!("a detail below the default level");
    tracing::info!(user = "alice", "sign-in checked");
    guard.shutdown().unwrap();
}

/// What a child process wrote.
struct ChildOutput {
    stdout: String,
    stderr: String,
}

/// Runs this program as a child with `variables` and returns what it writes.
fn run_child(variables: &[(&str, &OsStr)]) -> ChildOutput {
    let mut command = Command::new(std::env::current_exe().unwrap());
    // An override in the environment of the developer must not change the result.
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("AEGIS__")
        {
            command.env_remove(name);
        }
    }
    for (name, value) in variables {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "the child process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ChildOutput {
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// Runs the configuration child with `variables` and returns the line that it prints.
fn config_output(config: &Path, variables: &[(&str, &OsStr)]) -> String {
    let mut all = vec![(CHILD_CONFIG, config.as_os_str())];
    all.extend_from_slice(variables);
    run_child(&all).stdout.trim_end().to_owned()
}

fn load_with_env_reads_the_environment_of_the_process() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(DOCUMENT.as_bytes()).unwrap();
    let path = file.path();

    assert_eq!(
        config_output(path, &[]),
        "ok name=from-file batch_size=100 enabled=false",
        "with no override, the file values stay"
    );

    assert_eq!(
        config_output(
            path,
            &[
                ("AEGIS__INGEST__NAME", OsStr::new("from-env")),
                ("aegis__ingest__batch_size", OsStr::new("500")),
                ("AEGIS__INGEST__ENABLED", OsStr::new("true")),
                ("UNRELATED__INGEST__NAME", OsStr::new("ignored")),
            ]
        ),
        "ok name=from-env batch_size=500 enabled=true",
        "an override in the process environment wins over the file"
    );

    assert_eq!(
        config_output(path, &[("AEGIS__INGEST", OsStr::new("hunter2-s3cret"))]),
        "error configuration error: the environment variable AEGIS__INGEST is not a valid \
         override: use the form AEGIS__<SECTION>__<KEY> with a section and a key",
        "a bad override name is an error that does not show the value"
    );

    non_unicode_values(path);
}

/// Checks variables whose values are not Unicode. Only Unix permits such values.
#[cfg(unix)]
fn non_unicode_values(path: &Path) {
    use std::os::unix::ffi::OsStrExt;

    let not_unicode = OsStr::from_bytes(&[b'c', b'a', b'f', 0xff]);
    assert_eq!(
        config_output(path, &[("UNRELATED_VARIABLE", not_unicode)]),
        "ok name=from-file batch_size=100 enabled=false",
        "a variable without the prefix has no effect, also if it is not Unicode"
    );
    assert_eq!(
        config_output(path, &[("AEGIS__INGEST__NAME", not_unicode)]),
        "error configuration error: the environment variable AEGIS__INGEST__NAME must have a \
         name and a value in Unicode",
        "an override that is not Unicode is an error"
    );
}

/// Does nothing. Only Unix permits such values.
#[cfg(not(unix))]
fn non_unicode_values(_path: &Path) {}

fn init_writes_the_log_lines_to_the_standard_error_stream() {
    let text = run_child(&[(CHILD_LOG_FORMAT, OsStr::new("text"))]);
    assert_eq!(
        text.stdout, "",
        "the log does not go to the standard output"
    );
    let lines: Vec<&str> = text.stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "one event is at the default level: {lines:?}"
    );
    assert!(lines[0].contains(" INFO "), "{}", lines[0]);
    assert!(
        lines[0].ends_with("sign-in checked user=\"alice\""),
        "{}",
        lines[0]
    );

    let json = run_child(&[(CHILD_LOG_FORMAT, OsStr::new("json"))]);
    assert_eq!(
        json.stdout, "",
        "the log does not go to the standard output"
    );
    let lines: Vec<&str> = json.stderr.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "one event is at the default level: {lines:?}"
    );
    let event: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event["level"], "INFO");
    assert_eq!(
        event["fields"],
        serde_json::json!({"message": "sign-in checked", "user": "alice"})
    );
}
