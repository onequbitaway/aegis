//! The evidence archive: the detections, the events that caused them, and the states of
//! the incidents, in one bounded file.
//!
//! The detection engine keeps no event after it examined the event. The incident store
//! and the bus can be in the memory of the process. The commands that make documents for
//! other defenders (`aegis report abuse` and `aegis indicators export`) run after the
//! activity, and often in a different process. They read this archive.
//!
//! # The file
//!
//! The archive is JSON Lines. Each line is one [`EvidenceRecord`]:
//!
//! | `type` | Contents | Written when |
//! | --- | --- | --- |
//! | `event` | One normalized event that a detection names | The bridge records the detection |
//! | `detection` | One detection | The bridge records the detection |
//! | `incident` | One state of an incident, with the identifiers of its detections | The incident store takes a write |
//!
//! # The size limit
//!
//! The archive keeps at most `max_bytes` on the disk, in two files: the archive file and
//! one older file with the name of the archive file and `.1`. When the archive file has
//! half of the limit, it becomes the older file, and the file that was the older file
//! goes away. Thus the archive always holds the newest records.
//!
//! # Rules
//!
//! - The archive is not the audit log. A write that fails does not stop a detection. The
//!   archive counts the failure, and the log gets a line.
//! - The file holds raw log records. On Unix, only the owner can read it.
//! - A text of an event can come from an attacker. The archive keeps it as JSON data. No
//!   component runs it or uses it as an instruction.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use aegis_contracts::common::{DetectionId, EventId, IncidentId};
use aegis_contracts::event::Event;
use aegis_contracts::incident::Incident;
use aegis_contracts::{Detection, Error, Result};
use serde::{Deserialize, Serialize};

/// The number of event identifiers that the archive remembers as written.
const REMEMBERED_EVENTS: usize = 16_384;

/// The largest size of one line that the reader accepts: 8 MiB.
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

/// One line of the archive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceRecord {
    /// One normalized event that a detection names.
    Event {
        /// The event.
        event: Box<Event>,
    },
    /// One detection.
    Detection {
        /// The detection.
        detection: Box<Detection>,
    },
    /// One state of an incident.
    Incident {
        /// The incident. Its list of detections is empty: the archive has each detection
        /// one time, in a line of its own.
        incident: Box<Incident>,
        /// The identifiers of the detections of the incident, in order.
        detections: Vec<DetectionId>,
    },
}

/// The counts of one [`EvidenceArchive`] since the process started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvidenceStats {
    /// The records that the archive wrote.
    pub records_written: u64,
    /// The bytes that the archive wrote.
    pub bytes_written: u64,
    /// The records that the archive did not write: a write failed, or one record was
    /// larger than half of the size limit.
    pub records_dropped: u64,
    /// The number of times that the archive file became the older file.
    pub rotations: u64,
}

struct Writer {
    file: Option<File>,
    /// The size of the archive file.
    size: u64,
    /// The identifiers of the events that the archive wrote. An event of two detections
    /// has one line.
    written_events: HashSet<EventId>,
    written_order: VecDeque<EventId>,
    stats: EvidenceStats,
}

/// Writes the evidence archive of one application.
///
/// The bridge gives it each new detection with the events that caused the detection. The
/// incident store gives it each state of an incident.
pub struct EvidenceArchive {
    path: PathBuf,
    /// The largest size of one of the two files.
    file_limit: u64,
    writer: Mutex<Writer>,
}

/// Returns the path of the older file of an archive.
#[must_use]
pub fn older_file(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

fn open_for_append(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // The file holds raw log records. Only the owner can read it.
        options.mode(0o600);
    }
    options.open(path)
}

impl EvidenceArchive {
    /// Opens the archive file `path` for append. The function makes the directory of the
    /// file if it does not exist.
    ///
    /// `max_bytes` is the largest number of bytes that the archive keeps on the disk.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unavailable`] if the function cannot make the directory or open
    /// the file.
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64) -> Result<Self> {
        let path = path.into();
        let unavailable = |operation: &str, error: std::io::Error| {
            Error::Unavailable(format!(
                "cannot {operation} the evidence archive {}: {error}",
                path.display()
            ))
        };
        if let Some(directory) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(directory)
                .map_err(|error| unavailable("make the directory of", error))?;
        }
        let file = open_for_append(&path).map_err(|error| unavailable("open", error))?;
        let size = file
            .metadata()
            .map_err(|error| unavailable("read the size of", error))?
            .len();
        Ok(Self {
            path,
            file_limit: (max_bytes / 2).max(1),
            writer: Mutex::new(Writer {
                file: Some(file),
                size,
                written_events: HashSet::new(),
                written_order: VecDeque::new(),
                stats: EvidenceStats::default(),
            }),
        })
    }

    /// Returns the path of the archive file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the counts of the archive.
    #[must_use]
    pub fn stats(&self) -> EvidenceStats {
        self.lock().stats
    }

    fn lock(&self) -> MutexGuard<'_, Writer> {
        self.writer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records one write that did not succeed. The log gets a line for the first failure
    /// and then for each failure count that is a power of two.
    fn dropped(writer: &mut Writer, path: &Path, cause: &str) {
        writer.stats.records_dropped = writer.stats.records_dropped.saturating_add(1);
        if writer.stats.records_dropped.is_power_of_two() {
            tracing::warn!(
                archive = %path.display(),
                dropped = writer.stats.records_dropped,
                cause,
                "the evidence archive did not write a record"
            );
        }
    }

    /// Makes the archive file the older file, and starts a new archive file.
    fn rotate(&self, writer: &mut Writer) -> std::io::Result<()> {
        // Close the file before the rename.
        writer.file = None;
        std::fs::rename(&self.path, older_file(&self.path))?;
        writer.file = Some(open_for_append(&self.path)?);
        writer.size = 0;
        writer.stats.rotations = writer.stats.rotations.saturating_add(1);
        Ok(())
    }

    /// Writes one record as one line.
    fn write(&self, writer: &mut Writer, record: &EvidenceRecord) -> bool {
        let mut line = match serde_json::to_vec(record) {
            Ok(line) => line,
            Err(_) => {
                Self::dropped(writer, &self.path, "the record is not JSON");
                return false;
            }
        };
        line.push(b'\n');
        let length = line.len() as u64;
        if length > self.file_limit {
            Self::dropped(
                writer,
                &self.path,
                "the record is larger than the size limit",
            );
            return false;
        }
        if writer.size.saturating_add(length) > self.file_limit
            && let Err(error) = self.rotate(writer)
        {
            Self::dropped(writer, &self.path, &error.kind().to_string());
            // Try to open the file again at the next record.
            if writer.file.is_none() {
                writer.file = open_for_append(&self.path).ok();
            }
            return false;
        }
        if writer.file.is_none() {
            writer.file = open_for_append(&self.path).ok();
        }
        let Some(file) = writer.file.as_mut() else {
            Self::dropped(writer, &self.path, "the archive file is not open");
            return false;
        };
        match file.write_all(&line).and_then(|()| file.flush()) {
            Ok(()) => {
                writer.size = writer.size.saturating_add(length);
                writer.stats.records_written = writer.stats.records_written.saturating_add(1);
                writer.stats.bytes_written = writer.stats.bytes_written.saturating_add(length);
                true
            }
            Err(error) => {
                Self::dropped(writer, &self.path, &error.kind().to_string());
                false
            }
        }
    }

    /// Writes one detection and the events that caused it.
    ///
    /// `events` are the events of the detection that the caller has. An event that the
    /// archive wrote before gets no second line.
    pub fn record_detection(&self, detection: &Detection, events: &[Event]) {
        let mut writer = self.lock();
        for event in events {
            if writer.written_events.contains(&event.id) {
                continue;
            }
            let record = EvidenceRecord::Event {
                event: Box::new(event.clone()),
            };
            if self.write(&mut writer, &record) {
                writer.written_events.insert(event.id);
                writer.written_order.push_back(event.id);
                if writer.written_order.len() > REMEMBERED_EVENTS
                    && let Some(oldest) = writer.written_order.pop_front()
                {
                    writer.written_events.remove(&oldest);
                }
            }
        }
        let record = EvidenceRecord::Detection {
            detection: Box::new(detection.clone()),
        };
        self.write(&mut writer, &record);
    }

    /// Writes one state of an incident.
    pub fn record_incident(&self, incident: &Incident) {
        let detections = incident
            .detections
            .iter()
            .map(|detection| detection.id)
            .collect();
        let mut light = incident.clone();
        light.detections = Vec::new();
        let record = EvidenceRecord::Incident {
            incident: Box::new(light),
            detections,
        };
        let mut writer = self.lock();
        self.write(&mut writer, &record);
    }
}

/// The contents of an evidence archive.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EvidenceData {
    /// The events, in the order of the archive. Each event is in the list one time.
    pub events: Vec<Event>,
    /// The detections, in the order of the archive. Each detection is in the list one
    /// time.
    pub detections: Vec<Detection>,
    /// The last state of each incident, in the order of the first state. An incident has
    /// the detections that the archive holds.
    pub incidents: Vec<Incident>,
    /// For each incident, the number of its detections that the archive does not hold,
    /// because the size limit removed them.
    pub missing_detections: BTreeMap<IncidentId, usize>,
    /// The lines that are not records, for example a line that a stop of the process cut.
    pub invalid_lines: usize,
    /// The files that the reader read, oldest first.
    pub files: Vec<PathBuf>,
}

impl EvidenceData {
    /// Returns the last state of one incident.
    #[must_use]
    pub fn incident(&self, id: IncidentId) -> Option<&Incident> {
        self.incidents.iter().find(|incident| incident.id == id)
    }
}

/// Reads the archive file `path` and its older file. The function opens the files only to
/// read, so a service can write the archive at the same time.
///
/// A file that does not exist gives no records.
///
/// # Errors
///
/// Returns [`Error::Unavailable`] if a file exists and the function cannot read it.
pub fn read_archive(path: &Path) -> Result<EvidenceData> {
    let mut data = EvidenceData::default();
    let mut seen_events: HashSet<EventId> = HashSet::new();
    let mut detections: HashMap<DetectionId, usize> = HashMap::new();
    // The last state of each incident, with the identifiers of its detections.
    let mut states: Vec<(Incident, Vec<DetectionId>)> = Vec::new();
    let mut positions: HashMap<IncidentId, usize> = HashMap::new();

    for file_path in [older_file(path), path.to_path_buf()] {
        let file = match File::open(&file_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(Error::Unavailable(format!(
                    "cannot read the evidence archive {}: {error}",
                    file_path.display()
                )));
            }
        };
        data.files.push(file_path.clone());
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = reader
                .by_ref()
                .take(MAX_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|error| {
                    Error::Unavailable(format!(
                        "cannot read the evidence archive {}: {error}",
                        file_path.display()
                    ))
                })?;
            if read == 0 {
                break;
            }
            if line.len() > MAX_LINE_BYTES && !line.ends_with(b"\n") {
                // A line that is too long is not a record. Skip the rest of the line.
                data.invalid_lines += 1;
                let mut rest = Vec::new();
                loop {
                    rest.clear();
                    let more = reader
                        .by_ref()
                        .take(MAX_LINE_BYTES as u64)
                        .read_until(b'\n', &mut rest)
                        .map_err(|error| {
                            Error::Unavailable(format!(
                                "cannot read the evidence archive {}: {error}",
                                file_path.display()
                            ))
                        })?;
                    if more == 0 || rest.ends_with(b"\n") {
                        break;
                    }
                }
                continue;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice::<EvidenceRecord>(&line) {
                Ok(EvidenceRecord::Event { event }) => {
                    if seen_events.insert(event.id) {
                        data.events.push(*event);
                    }
                }
                Ok(EvidenceRecord::Detection { detection }) => {
                    match detections.get(&detection.id) {
                        Some(position) => data.detections[*position] = *detection,
                        None => {
                            detections.insert(detection.id, data.detections.len());
                            data.detections.push(*detection);
                        }
                    }
                }
                Ok(EvidenceRecord::Incident {
                    incident,
                    detections: ids,
                }) => match positions.get(&incident.id) {
                    Some(position) => states[*position] = (*incident, ids),
                    None => {
                        positions.insert(incident.id, states.len());
                        states.push((*incident, ids));
                    }
                },
                Err(_) => data.invalid_lines += 1,
            }
        }
    }

    for (mut incident, ids) in states {
        let mut missing = 0_usize;
        for id in ids {
            match detections.get(&id) {
                Some(position) => incident.detections.push(data.detections[*position].clone()),
                None => missing += 1,
            }
        }
        if missing > 0 {
            data.missing_detections.insert(incident.id, missing);
        }
        data.incidents.push(incident);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use aegis_contracts::common::{EntityKind, Severity};
    use aegis_contracts::detection::{DetectionTier, Verdict};
    use aegis_contracts::event::{Actor, EventClass, EventSource, action};
    use aegis_contracts::incident::IncidentStatus;
    use chrono::{DateTime, TimeDelta, Utc};

    use super::*;

    fn time(second: i64) -> DateTime<Utc> {
        DateTime::UNIX_EPOCH + TimeDelta::seconds(1_800_000_000 + second)
    }

    fn event(second: i64, note: &str) -> Event {
        Event::new(
            time(second),
            EventSource::new("idp", "example", "identity"),
            EventClass::Authentication,
            action::SIGN_IN,
            Actor::new(EntityKind::User, "user-1"),
        )
        .with_attribute("note", note)
    }

    fn detection(events: &[Event]) -> Detection {
        Detection {
            id: DetectionId::new(),
            rule_id: "rule-1".to_owned(),
            title: "A detection".to_owned(),
            description: "A test detection.".to_owned(),
            severity: Severity::High,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time: time(0),
            attack: Vec::new(),
            event_ids: events.iter().map(|event| event.id).collect(),
            entities: Vec::new(),
            tenant: None,
            attributes: BTreeMap::new(),
        }
    }

    fn incident(detections: Vec<Detection>) -> Incident {
        Incident {
            id: IncidentId::new(),
            title: "An incident".to_owned(),
            summary: "A test incident.".to_owned(),
            severity: Severity::High,
            status: IncidentStatus::Open,
            created_at: time(0),
            updated_at: time(0),
            tenant: None,
            detections,
            entities: Vec::new(),
            attack: Vec::new(),
            timeline: Vec::new(),
        }
    }

    #[test]
    fn the_reader_gives_each_event_one_time_and_the_last_state_of_each_incident() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data/evidence.jsonl");
        let archive = EvidenceArchive::open(&path, 1024 * 1024).unwrap();
        assert_eq!(archive.path(), path);
        let events = [event(1, "a"), event(2, "b"), event(3, "c")];
        let first = detection(&events[..2]);
        // The second detection names one event of the first detection again.
        let second = detection(&events[1..]);

        archive.record_detection(&first, &events[..2]);
        let mut state = incident(vec![first.clone()]);
        archive.record_incident(&state);
        archive.record_detection(&second, &events[1..]);
        state.detections.push(second.clone());
        state.status = IncidentStatus::Investigating;
        archive.record_incident(&state);

        // Three events, two detections, and two states of the incident.
        assert_eq!(archive.stats().records_written, 7);
        assert_eq!(archive.stats().records_dropped, 0);
        assert_eq!(archive.stats().rotations, 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 7);
        assert_eq!(archive.stats().bytes_written, text.len() as u64);
        let types: Vec<String> = text
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["type"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            types,
            [
                "event",
                "event",
                "detection",
                "incident",
                "event",
                "detection",
                "incident"
            ]
        );

        let data = read_archive(&path).unwrap();
        assert_eq!(data.events, events);
        assert_eq!(data.detections, [first, second]);
        assert_eq!(data.incidents, [state.clone()]);
        assert_eq!(data.incident(state.id), Some(&state));
        assert_eq!(data.incident(IncidentId::new()), None);
        assert_eq!(data.missing_detections, BTreeMap::new());
        assert_eq!(data.invalid_lines, 0);
        assert_eq!(data.files, [path]);
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_the_archive_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let archive = EvidenceArchive::open(&path, 1024 * 1024).unwrap();
        archive.record_detection(&detection(&[]), &[]);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn the_archive_keeps_the_newest_records_in_the_size_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let limit = 64 * 1024_u64;
        let archive = EvidenceArchive::open(&path, limit).unwrap();
        let note = "x".repeat(1000);
        let mut all = Vec::new();
        for second in 0..200 {
            let event = event(second, &note);
            archive.record_detection(
                &detection(std::slice::from_ref(&event)),
                std::slice::from_ref(&event),
            );
            all.push(event);
        }

        let stats = archive.stats();
        assert_eq!(stats.records_written, 400);
        assert_eq!(stats.records_dropped, 0);
        assert!(stats.rotations >= 4, "{stats:?}");
        // The two files together are not larger than the limit.
        let current = std::fs::metadata(&path).unwrap().len();
        let older = std::fs::metadata(older_file(&path)).unwrap().len();
        assert!(current <= limit / 2, "{current}");
        assert!(older <= limit / 2, "{older}");
        assert!(older > limit / 4, "{older}");

        // The reader has the newest events, in order, and not the oldest events.
        let data = read_archive(&path).unwrap();
        assert_eq!(data.files, [older_file(&path), path.clone()]);
        assert!(data.events.len() >= 20, "{}", data.events.len());
        assert!(data.events.len() < 100, "{}", data.events.len());
        assert_eq!(data.events[..], all[all.len() - data.events.len()..]);
        assert_eq!(data.invalid_lines, 0);

        // A record that is larger than one file is not written.
        let large = event(999, &"y".repeat(limit as usize));
        archive.record_detection(&detection(&[]), &[large]);
        let stats = archive.stats();
        assert_eq!(stats.records_dropped, 1);
        assert_eq!(stats.records_written, 401);
    }

    #[test]
    fn a_state_of_an_incident_names_the_detections_that_the_limit_removed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let archive = EvidenceArchive::open(&path, 1024 * 1024).unwrap();
        let kept = detection(&[]);
        let removed = detection(&[]);
        archive.record_detection(&kept, &[]);
        let state = incident(vec![removed.clone(), kept.clone()]);
        archive.record_incident(&state);

        let data = read_archive(&path).unwrap();
        assert_eq!(data.incidents.len(), 1);
        assert_eq!(data.incidents[0].detections, [kept]);
        assert_eq!(
            data.missing_detections,
            BTreeMap::from([(state.id, 1_usize)])
        );
    }

    #[test]
    fn a_line_that_is_not_a_record_is_counted_and_the_other_lines_are_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let archive = EvidenceArchive::open(&path, 1024 * 1024).unwrap();
        let first = event(1, "a");
        archive.record_detection(
            &detection(std::slice::from_ref(&first)),
            std::slice::from_ref(&first),
        );
        drop(archive);
        // A stop of the process cut the last line. A second process then adds records.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"type\":\"event\",\"event\":{\"id\":\n\nnot json\n{\"type\":\"other\"}\n");
        std::fs::write(&path, text).unwrap();
        let archive = EvidenceArchive::open(&path, 1024 * 1024).unwrap();
        let second = event(2, "b");
        archive.record_detection(
            &detection(std::slice::from_ref(&second)),
            std::slice::from_ref(&second),
        );

        let data = read_archive(&path).unwrap();
        assert_eq!(data.events, [first, second]);
        assert_eq!(data.detections.len(), 2);
        assert_eq!(data.invalid_lines, 3);
    }

    #[test]
    fn an_archive_that_does_not_exist_has_no_records() {
        let directory = tempfile::tempdir().unwrap();
        let data = read_archive(&directory.path().join("missing.jsonl")).unwrap();
        assert_eq!(data, EvidenceData::default());
    }

    #[test]
    fn a_directory_that_cannot_be_made_is_an_unavailable_error() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, "x").unwrap();
        let error = EvidenceArchive::open(file.join("evidence.jsonl"), 1024 * 1024)
            .err()
            .unwrap();
        assert!(
            matches!(&error, Error::Unavailable(message)
                if message.starts_with("cannot make the directory of the evidence archive ")),
            "{error:?}"
        );
    }
}
