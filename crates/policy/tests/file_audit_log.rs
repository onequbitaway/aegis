//! Tests for the file audit log through its public interface.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::audit::{
    AuditEntry, AuditKind, AuditLog, AuditRecord, ChainVerification, GENESIS_HASH, canonical_json,
    seal,
};
use aegis_contracts::common::{EvidenceKind, EvidenceRef};
use aegis_policy::FileAuditLog;
use chrono::Utc;
use serde_json::json;

fn entry(index: usize) -> AuditEntry {
    AuditEntry::new(
        AuditKind::ActionExecuted,
        "responder",
        format!("Step {index} is complete."),
    )
    .with_payload(json!({ "index": index, "nested": { "b": [1, 2.5, null], "a": true } }))
    .with_evidence(vec![EvidenceRef::new(EvidenceKind::Incident, "inc-1")])
}

async fn append(log: &FileAuditLog, count: usize) -> Vec<AuditRecord> {
    let mut records = Vec::new();
    for index in 0..count {
        records.push(log.append(entry(index)).await.unwrap());
    }
    records
}

/// Makes a log file with `count` records and closes the log.
async fn closed_log(path: &Path, count: usize) -> Vec<AuditRecord> {
    let log = FileAuditLog::open(path).unwrap();
    append(&log, count).await
}

fn lines(path: &Path) -> Vec<String> {
    let text = fs::read_to_string(path).unwrap();
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "the file must end with a line feed"
    );
    text.lines().map(str::to_owned).collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    let mut text = lines.join("\n");
    text.push('\n');
    fs::write(path, text).unwrap();
}

fn integrity_message(result: aegis_contracts::Result<FileAuditLog>) -> String {
    match result {
        Err(Error::Integrity(message)) => message,
        Err(other) => panic!("expected an integrity error, found {other:?}"),
        Ok(_) => panic!("expected an integrity error, found an open log"),
    }
}

fn assert_invalid(report: &ChainVerification, checked: u64, sequence: u64, case: &str) {
    assert!(!report.valid, "{case}: {report:?}");
    assert_eq!(
        report.first_invalid_sequence,
        Some(sequence),
        "{case}: {report:?}"
    );
    assert_eq!(report.checked, checked, "{case}: {report:?}");
    assert!(report.reason.is_some(), "{case}");
}

fn assert_valid(report: &ChainVerification, checked: u64) {
    assert_eq!(
        report,
        &ChainVerification {
            valid: true,
            checked,
            first_invalid_sequence: None,
            reason: None
        }
    );
}

#[tokio::test]
async fn append_seals_a_chain_and_read_returns_the_same_records() {
    let directory = tempfile::tempdir().unwrap();
    let log = FileAuditLog::open(directory.path().join("audit.jsonl")).unwrap();
    assert_eq!(log.head(), None);
    assert_eq!(log.read(1, 10).await.unwrap(), Vec::new());
    assert_valid(&log.verify().await.unwrap(), 0);

    let records = append(&log, 5).await;
    assert_eq!(
        records
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    assert_eq!(records[0].prev_hash, GENESIS_HASH);
    for pair in records.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
        assert_eq!(pair[1].hash, pair[1].compute_hash().unwrap());
    }
    assert_eq!(records[2].summary, "Step 2 is complete.");
    assert_eq!(log.head().as_ref(), records.last());

    assert_eq!(log.read(1, 100).await.unwrap(), records);
    assert_eq!(log.read(0, 2).await.unwrap(), records[..2]);
    assert_eq!(log.read(2, 2).await.unwrap(), records[1..3]);
    assert_eq!(log.read(4, usize::MAX).await.unwrap(), records[3..]);
    assert_eq!(log.read(5, 1).await.unwrap(), records[4..]);
    assert_eq!(log.read(6, 10).await.unwrap(), Vec::new());
    assert_eq!(log.read(3, 0).await.unwrap(), Vec::new());
    assert_valid(&log.verify().await.unwrap(), 5);
}

#[tokio::test]
async fn each_record_is_one_line_in_the_file_when_append_returns() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    for index in 0..3 {
        let record = log.append(entry(index)).await.unwrap();
        let lines = lines(&path);
        assert_eq!(lines.len(), index + 1);
        let on_disk: AuditRecord = serde_json::from_str(&lines[index]).unwrap();
        assert_eq!(on_disk, record);
        assert_eq!(
            lines[index],
            canonical_json(&serde_json::to_value(&record).unwrap()),
            "a line is the canonical form of its record"
        );
    }
}

#[tokio::test]
async fn a_change_to_any_byte_is_detected_at_its_record() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    append(&log, 4).await;
    let original = fs::read(&path).unwrap();
    assert!(
        original.len() > 1000,
        "the file has {} bytes",
        original.len()
    );
    assert_eq!(original.iter().filter(|byte| **byte == b'\n').count(), 4);

    let mut checks = 0;
    for position in 0..original.len() {
        // A line feed is the last byte of its line.
        let line = original[..position]
            .iter()
            .filter(|byte| **byte == b'\n')
            .count();
        let start = original[..position]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let end = start
            + original[start..]
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap();
        for mask in [0x01_u8, 0x20, 0x80] {
            let mut changed = original.clone();
            changed[position] ^= mask;
            // A line that still holds a record gives the sequence number that the record
            // states. All other lines give the sequence number of their position.
            let expected = match serde_json::from_slice::<AuditRecord>(&changed[start..end]) {
                Ok(record) if position != end => record.sequence,
                _ => line as u64 + 1,
            };
            fs::write(&path, &changed).unwrap();
            let case = format!("byte {position} with mask {mask:#04x}");
            let report = log.verify().await.unwrap();
            assert_invalid(&report, line as u64, expected, &case);
            assert_eq!(FileAuditLog::verify_file(&path).unwrap(), report, "{case}");
            checks += 1;
        }
    }
    assert_eq!(checks, original.len() * 3);

    fs::write(&path, &original).unwrap();
    assert_valid(&log.verify().await.unwrap(), 4);
}

#[tokio::test]
async fn a_removed_line_is_detected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    append(&log, 4).await;
    let original = lines(&path);
    assert_eq!(original.len(), 4);

    // (index of the removed line, records before the fault, first invalid sequence)
    for (removed, checked, sequence) in [(0, 0, 2), (1, 1, 3), (2, 2, 4), (3, 3, 4)] {
        let mut changed = original.clone();
        changed.remove(removed);
        write_lines(&path, &changed);
        let report = log.verify().await.unwrap();
        assert_invalid(
            &report,
            checked,
            sequence,
            &format!("line {removed} removed"),
        );
    }

    // The file alone does not show that its last line is gone. The open log knows its
    // last record, so the check above finds the removal.
    assert_valid(&FileAuditLog::verify_file(&path).unwrap(), 3);

    write_lines(&path, &original);
    assert_valid(&log.verify().await.unwrap(), 4);
}

#[tokio::test]
async fn a_line_in_a_different_position_is_detected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    append(&log, 4).await;
    let original = lines(&path);

    // (the two lines to exchange, records before the fault, first invalid sequence)
    for (left, right, checked, sequence) in [(1, 2, 1, 3), (0, 3, 0, 4), (2, 3, 2, 4)] {
        let mut changed = original.clone();
        changed.swap(left, right);
        write_lines(&path, &changed);
        let report = log.verify().await.unwrap();
        assert_invalid(
            &report,
            checked,
            sequence,
            &format!("lines {left} and {right}"),
        );
        assert_eq!(FileAuditLog::verify_file(&path).unwrap(), report);
    }

    let mut duplicate = original.clone();
    duplicate.insert(2, original[1].clone());
    write_lines(&path, &duplicate);
    assert_invalid(
        &FileAuditLog::verify_file(&path).unwrap(),
        2,
        2,
        "line 1 two times",
    );
}

#[tokio::test]
async fn a_reopened_log_continues_the_chain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let first = closed_log(&path, 3).await;

    let log = FileAuditLog::open(&path).unwrap();
    assert_eq!(log.head().as_ref(), first.last());
    let fourth = log.append(entry(3)).await.unwrap();
    assert_eq!(fourth.sequence, 4);
    assert_eq!(fourth.prev_hash, first[2].hash);

    let all = log.read(1, 10).await.unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(all[..3], first);
    assert_eq!(all[3], fourth);
    assert_valid(&log.verify().await.unwrap(), 4);
    drop(log);
    assert_valid(&FileAuditLog::verify_file(&path).unwrap(), 4);
}

#[tokio::test]
async fn a_tampered_log_does_not_open_for_append() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    closed_log(&path, 3).await;
    let original = lines(&path);

    let mut changed_record = original.clone();
    changed_record[1] = changed_record[1].replace("Step 1 is complete.", "Step 1 is not done.");
    assert_ne!(changed_record[1], original[1]);
    let mut removed = original.clone();
    removed.remove(1);
    let mut exchanged = original.clone();
    exchanged.swap(0, 1);
    let mut not_json = original.clone();
    not_json[2] = "not a record".to_owned();

    let cases = [
        (
            "a changed record",
            changed_record,
            "first invalid sequence 2:",
        ),
        ("a removed line", removed, "first invalid sequence 3:"),
        ("exchanged lines", exchanged, "first invalid sequence 2:"),
        (
            "a line that is not JSON",
            not_json,
            "first invalid sequence 3:",
        ),
    ];
    for (case, changed, fragment) in cases {
        write_lines(&path, &changed);
        let before = fs::read(&path).unwrap();
        let message = integrity_message(FileAuditLog::open(&path));
        assert!(message.contains(fragment), "{case}: {message}");
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{case}: open must not change the file"
        );
    }

    write_lines(&path, &original);
    let log = FileAuditLog::open(&path).unwrap();
    assert_eq!(log.append(entry(3)).await.unwrap().sequence, 4);
}

#[tokio::test]
async fn a_partial_last_line_is_reported_and_not_repaired() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    closed_log(&path, 2).await;
    let complete = fs::read(&path).unwrap();

    // A write of the third record that stopped before the end of the line.
    let third = seal(None, entry(2), Utc::now()).unwrap();
    let third_line = canonical_json(&serde_json::to_value(&third).unwrap());
    let mut partial = complete.clone();
    partial.extend_from_slice(&third_line.as_bytes()[..third_line.len() / 2]);
    // The line is complete, but its line feed is not there.
    let mut no_line_feed = complete.clone();
    no_line_feed.pop();
    // The cut is in the second record.
    let cut = complete[..complete.len() - 40].to_vec();

    for (case, bytes, checked, sequence) in [
        ("half of a third line", partial, 2, 3),
        ("no line feed after the last line", no_line_feed, 1, 2),
        ("a cut in the last record", cut, 1, 2),
    ] {
        fs::write(&path, &bytes).unwrap();
        let message = integrity_message(FileAuditLog::open(&path));
        assert!(
            message.contains(&format!("first invalid sequence {sequence}:")),
            "{case}: {message}"
        );
        assert!(message.contains("not complete"), "{case}: {message}");
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "{case}: open must not repair the file"
        );
        let report = FileAuditLog::verify_file(&path).unwrap();
        assert_invalid(&report, checked, sequence, case);
    }
}

#[tokio::test]
async fn a_second_writer_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let first = FileAuditLog::open(&path).unwrap();
    first.append(entry(0)).await.unwrap();

    fs::create_dir(directory.path().join("sub")).unwrap();
    let other_spelling = directory.path().join("sub").join("..").join("audit.jsonl");
    for second_path in [path.clone(), other_spelling] {
        let error = FileAuditLog::open(&second_path).unwrap_err();
        assert!(
            matches!(&error, Error::Unavailable(message) if message.contains("audit.jsonl")),
            "{}: {error:?}",
            second_path.display()
        );
        assert!(error.is_retryable());
    }
    // The refused writers changed nothing, and the first writer continues.
    assert_eq!(first.append(entry(1)).await.unwrap().sequence, 2);
    assert_valid(&first.verify().await.unwrap(), 2);

    drop(first);
    let next = FileAuditLog::open(&path).unwrap();
    assert_eq!(next.append(entry(2)).await.unwrap().sequence, 3);
}

#[cfg(unix)]
#[tokio::test]
async fn a_symbolic_link_to_an_open_log_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let link = directory.path().join("link.jsonl");
    let first = FileAuditLog::open(&path).unwrap();
    std::os::unix::fs::symlink(&path, &link).unwrap();

    let error = FileAuditLog::open(&link).unwrap_err();
    assert!(matches!(error, Error::Unavailable(_)), "{error:?}");

    drop(first);
    let through_link = FileAuditLog::open(&link).unwrap();
    assert_eq!(through_link.path(), fs::canonicalize(&path).unwrap());
}

#[cfg(unix)]
#[tokio::test]
async fn a_hard_link_to_an_open_log_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let link = directory.path().join("second-name.jsonl");
    let first = FileAuditLog::open(&path).unwrap();
    let records = append(&first, 2).await;
    fs::hard_link(&path, &link).unwrap();

    // The second name has its own lock file, which no writer holds.
    let error = FileAuditLog::open(&link).unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("second-name.jsonl")),
        "{error:?}"
    );
    assert_eq!(first.append(entry(2)).await.unwrap().sequence, 3);

    drop(first);
    let through_link = FileAuditLog::open(&link).unwrap();
    assert_eq!(through_link.read(1, 2).await.unwrap(), records);
    assert_eq!(through_link.append(entry(3)).await.unwrap().sequence, 4);
}

#[tokio::test]
async fn bytes_from_a_different_writer_stop_the_log() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    let records = append(&log, 2).await;

    // A different writer adds a record that continues the chain correctly.
    let foreign = seal(records.last(), entry(2), Utc::now()).unwrap();
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(
        file,
        "{}",
        canonical_json(&serde_json::to_value(&foreign).unwrap())
    )
    .unwrap();
    drop(file);
    assert_valid(&FileAuditLog::verify_file(&path).unwrap(), 3);

    let report = log.verify().await.unwrap();
    assert_invalid(&report, 2, 3, "a record from a different writer");

    for attempt in 0..2 {
        let error = log.append(entry(3)).await.unwrap_err();
        assert!(
            matches!(error, Error::Integrity(_)),
            "attempt {attempt}: {error:?}"
        );
    }
    assert_eq!(lines(&path).len(), 3, "a refused append must not write");
    assert_eq!(log.read(1, 10).await.unwrap(), records);
}

#[tokio::test]
async fn a_file_that_lost_its_last_bytes_stops_the_log() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    append(&log, 3).await;
    let original = lines(&path);
    write_lines(&path, &original[..2]);

    let error = log.append(entry(3)).await.unwrap_err();
    assert!(matches!(error, Error::Integrity(_)), "{error:?}");
    assert_eq!(
        lines(&path),
        original[..2],
        "a refused append must not write"
    );
    let error = log.read(1, 10).await.unwrap_err();
    assert!(
        matches!(&error, Error::Integrity(message) if message.contains("sequence 3")),
        "{error:?}"
    );
    assert_eq!(log.read(1, 2).await.unwrap().len(), 2);
}

#[cfg(unix)]
#[tokio::test]
async fn a_file_that_was_replaced_or_removed_stops_the_log() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let moved = directory.path().join("audit.jsonl.1");

    let log = FileAuditLog::open(&path).unwrap();
    append(&log, 2).await;
    // The usual log rotation: rename the file and make a new file with the same name.
    fs::rename(&path, &moved).unwrap();
    fs::copy(&moved, &path).unwrap();
    assert_invalid(&log.verify().await.unwrap(), 2, 3, "a replaced file");
    let error = log.append(entry(2)).await.unwrap_err();
    assert!(matches!(error, Error::Integrity(_)), "{error:?}");
    assert_eq!(
        lines(&moved).len(),
        2,
        "a refused append must not write to the old file"
    );
    assert_eq!(
        lines(&path).len(),
        2,
        "a refused append must not write to the new file"
    );
    drop(log);

    let log = FileAuditLog::open(&path).unwrap();
    append(&log, 1).await;
    fs::remove_file(&path).unwrap();
    assert_invalid(&log.verify().await.unwrap(), 0, 1, "a removed file");
    let error = log.append(entry(3)).await.unwrap_err();
    assert!(matches!(error, Error::Integrity(_)), "{error:?}");
}

#[tokio::test]
async fn read_fails_when_a_record_changed_on_the_disk() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();
    append(&log, 4).await;
    let mut changed = lines(&path);
    changed[2] = changed[2].replace("Step 2 is complete.", "Step 2 is not done.");
    write_lines(&path, &changed);

    assert_eq!(
        log.read(1, 2).await.unwrap().len(),
        2,
        "the records before the change are correct"
    );
    for (from, limit) in [(1, 10), (3, 1), (2, 2)] {
        let error = log.read(from, limit).await.unwrap_err();
        assert!(
            matches!(&error, Error::Integrity(message) if message.contains("first invalid sequence 3:")),
            "read({from}, {limit}): {error:?}"
        );
    }
    // The fourth record is correct, and it continues the hash that the third line states.
    let fourth = log.read(4, 1).await.unwrap();
    assert_eq!(fourth.len(), 1);
    assert_eq!(fourth[0].sequence, 4);
}

/// The numbers come from a fixed sequence, so the test is the same in each run.
fn sample_numbers(count: usize) -> Vec<f64> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut numbers = Vec::with_capacity(count);
    while numbers.len() < count {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let number = f64::from_bits(state);
        if number.is_finite() {
            numbers.push(number);
        }
    }
    numbers
}

#[tokio::test]
async fn numbers_in_a_payload_keep_their_value_after_a_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit.jsonl");
    let numbers = sample_numbers(3000);
    let payload = json!({
        "numbers": numbers,
        "integers": [0, -1, u64::MAX, i64::MIN],
        "fractions": [0.1, 1.0, 1e300, 5e-324, -0.0, 2.5e-8],
        "text": "é \u{1F512} \"quoted\" \\ \n line",
    });
    let log = FileAuditLog::open(&path).unwrap();
    let record = log
        .append(AuditEntry::new(AuditKind::Other, "test", "Numbers.").with_payload(payload.clone()))
        .await
        .unwrap();
    assert_eq!(record.payload, payload);
    drop(log);

    assert_eq!(
        lines(&path).len(),
        1,
        "a line feed in a string must not split the line"
    );
    let log = FileAuditLog::open(&path).unwrap();
    assert_valid(&log.verify().await.unwrap(), 1);
    assert_eq!(log.read(1, 1).await.unwrap(), [record]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn appends_from_many_tasks_make_one_chain() {
    const TASKS: usize = 6;
    const APPENDS: usize = 8;
    let directory = tempfile::tempdir().unwrap();
    let log = Arc::new(FileAuditLog::open(directory.path().join("audit.jsonl")).unwrap());

    let mut workers = Vec::new();
    for task in 0..TASKS {
        let log = Arc::clone(&log);
        workers.push(tokio::spawn(async move {
            let mut sequences = Vec::new();
            for index in 0..APPENDS {
                let record = log.append(entry(task * 100 + index)).await.unwrap();
                sequences.push(record.sequence);
            }
            sequences
        }));
    }
    let mut sequences = BTreeSet::new();
    for worker in workers {
        let own = tokio::time::timeout(Duration::from_secs(120), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(
            own.is_sorted(),
            "one task sees its records in order: {own:?}"
        );
        sequences.extend(own);
    }
    let total = (TASKS * APPENDS) as u64;
    assert_eq!(sequences, (1..=total).collect::<BTreeSet<u64>>());
    assert_valid(&log.verify().await.unwrap(), total);
    let records = log.read(1, usize::MAX).await.unwrap();
    assert_eq!(
        records
            .iter()
            .map(|record| record.sequence)
            .collect::<Vec<_>>(),
        (1..=total).collect::<Vec<u64>>()
    );
}

#[tokio::test]
async fn the_log_works_as_an_audit_log_trait_object() {
    let directory = tempfile::tempdir().unwrap();
    let log: Arc<dyn AuditLog> =
        Arc::new(FileAuditLog::open(directory.path().join("audit.jsonl")).unwrap());
    let record = log.append(entry(0)).await.unwrap();
    assert_eq!(record.sequence, 1);
    assert_eq!(log.read(1, 1).await.unwrap(), [record]);
    assert_valid(&log.verify().await.unwrap(), 1);
}

#[test]
fn the_log_works_without_a_tokio_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let log = FileAuditLog::open(directory.path().join("audit.jsonl")).unwrap();
    let record = futures::executor::block_on(log.append(entry(0))).unwrap();
    assert_eq!(record.sequence, 1);
    assert_eq!(
        futures::executor::block_on(log.read(1, 5)).unwrap(),
        [record]
    );
    assert_valid(&futures::executor::block_on(log.verify()).unwrap(), 1);
}

#[test]
fn a_path_that_cannot_hold_a_log_is_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");

    let error = FileAuditLog::verify_file(missing.join("audit.jsonl")).unwrap_err();
    assert!(matches!(error, Error::NotFound(_)), "{error:?}");

    let error = FileAuditLog::open(missing.join("audit.jsonl")).unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("missing")),
        "{error:?}"
    );

    let error = FileAuditLog::open(directory.path()).unwrap_err();
    assert!(matches!(error, Error::Config(_)), "{error:?}");
}
