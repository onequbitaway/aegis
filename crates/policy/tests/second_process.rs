//! A test that a second process cannot open an audit log that has a writer.
//!
//! This program has no test harness. Without the environment variable [`CHILD_PATH`], it
//! is the test. With the variable, it is the second process: it tries to open the log at
//! that path, and its exit code tells the result.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, exit};

use aegis_contracts::Error;
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog, ChainVerification};
use aegis_policy::FileAuditLog;
use futures::executor::block_on;

/// The environment variable that gives the path of the log to the second process.
const CHILD_PATH: &str = "AEGIS_POLICY_TEST_SECOND_WRITER_LOG";

/// The second process opened the log and appended one record.
const OPENED: i32 = 20;
/// The second process got [`Error::Unavailable`], and the error is retryable.
const REJECTED: i32 = 21;
/// The second process got a different result.
const UNEXPECTED: i32 = 22;

fn entry(summary: &str) -> AuditEntry {
    AuditEntry::new(AuditKind::Other, "test", summary)
}

/// The name of the test in the list that a test runner asks for.
const TEST_NAME: &str = "a_second_process_cannot_open_a_log_that_has_a_writer";

fn main() {
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        exit(second_process(Path::new(&path)));
    }
    // A test runner can ask for the list of tests. The program must not run the test then.
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.iter().any(|argument| argument == "--list") {
        if !arguments.iter().any(|argument| argument == "--ignored") {
            println!("{TEST_NAME}: test");
        }
        return;
    }
    first_process();
}

fn second_process(path: &Path) -> i32 {
    match FileAuditLog::open(path) {
        Ok(log) => match block_on(log.append(entry("From the second process."))) {
            Ok(_) => OPENED,
            Err(error) => {
                eprintln!("the second process opened the log but could not append: {error}");
                UNEXPECTED
            }
        },
        Err(error @ Error::Unavailable(_)) if error.is_retryable() => REJECTED,
        Err(error) => {
            eprintln!("the second process got an error of the wrong type: {error:?}");
            UNEXPECTED
        }
    }
}

/// Starts this program again as the second process and returns its exit code.
fn run_second_process(path: &Path) -> i32 {
    let output = Command::new(std::env::current_exe().unwrap())
        .env(CHILD_PATH, path)
        .output()
        .unwrap();
    output.status.code().unwrap_or_else(|| {
        panic!(
            "the second process had no exit code: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn first_process() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    block_on(log.append(entry("First."))).unwrap();
    block_on(log.append(entry("Second."))).unwrap();
    let before = std::fs::read(&path).unwrap();

    assert_eq!(
        run_second_process(&path),
        REJECTED,
        "a second process must not open a log that has a writer"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the refused process must not change the file"
    );
    // The first writer continues after the refused attempt.
    let third = block_on(log.append(entry("Third."))).unwrap();
    assert_eq!(third.sequence, 3);

    drop(log);
    assert_eq!(
        run_second_process(&path),
        OPENED,
        "a process must open the log after the first writer closed it"
    );
    assert_eq!(
        FileAuditLog::verify_file(&path).unwrap(),
        ChainVerification {
            valid: true,
            checked: 4,
            first_invalid_sequence: None,
            reason: None
        },
        "the record of the second process must continue the chain"
    );
    println!("test {TEST_NAME} ... ok");
}
