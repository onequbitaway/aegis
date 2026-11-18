//! An audit log in one append-only JSON Lines file.
//!
//! [`FileAuditLog`] is for a deployment that has no database. It keeps the full hash chain
//! in one file.
//!
//! # File format
//!
//! Each line is one [`AuditRecord`] in canonical JSON form, with a line feed after it.
//! Refer to [`canonical_json`]. The first line holds sequence number 1.
//!
//! # What the log detects
//!
//! [`FileAuditLog::open`] and [`AuditLog::verify`] read the file from the disk. They find:
//!
//! - A change to a byte of a record. The check uses [`verify_chain`]. It also compares each
//!   line with the canonical form of its record, so a change that keeps the record equal
//!   is found too.
//! - A removed line and a line in a different position.
//! - A last line that is not complete, which a failure during a write can cause.
//! - Bytes that a different process added after the last record of this process.
//!
//! [`AuditLog::verify`] also finds a removed last line, because the log keeps its last
//! record in memory. After a restart, the log cannot find that the last lines are gone:
//! a shorter chain is also a correct chain. To find this, keep the sequence number and the
//! hash from [`FileAuditLog::head`] in a different system and compare them after a restart.
//!
//! # First invalid sequence
//!
//! For a line that holds a record, the first invalid sequence is the value that
//! [`verify_chain`] gives: the sequence number that the first incorrect record states. For
//! a line that does not hold a record, it is the sequence number that the position of the
//! line must have.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aegis_contracts::audit::{
    AuditEntry, AuditLog, AuditRecord, ChainVerification, canonical_json, seal, verify_chain,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// The configuration of a [`FileAuditLog`].
///
/// Each subsystem reads its own table of the AEGIS configuration file. This type is the
/// table of the file audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAuditLogConfig {
    /// The path of the log file. The directory of the file must exist.
    pub path: PathBuf,
}

/// The log keeps the byte offset of one line in each group of this many lines.
const CHECKPOINT_STRIDE: u64 = 256;

/// The number of records that one call to [`verify_chain`] checks.
const VERIFY_BATCH: usize = 256;

/// The operations that the log does on its file.
///
/// The tests replace the file with an implementation that fails on command.
trait Storage: Send + 'static {
    /// Returns the length of the file in bytes.
    fn len(&self) -> io::Result<u64>;

    /// Returns `true` if `path` refers to this file.
    fn is_at(&self, path: &Path) -> io::Result<bool>;

    /// Writes `line` at the end of the file and syncs it to the disk.
    fn append(&mut self, line: &[u8]) -> io::Result<()>;

    /// Sets the length of the file and syncs the change to the disk.
    fn truncate(&mut self, len: u64) -> io::Result<()>;
}

impl Storage for File {
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    fn is_at(&self, path: &Path) -> io::Result<bool> {
        same_file(self, path)
    }

    fn append(&mut self, line: &[u8]) -> io::Result<()> {
        self.write_all(line)?;
        self.sync_data()
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.set_len(len)?;
        self.sync_all()
    }
}

#[cfg(unix)]
fn same_file(file: &File, path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let ours = file.metadata()?;
    match fs::metadata(path) {
        Ok(theirs) => Ok(ours.dev() == theirs.dev() && ours.ino() == theirs.ino()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn same_file(_file: &File, path: &Path) -> io::Result<bool> {
    path.try_exists()
}

/// The first incorrect line that a scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fault {
    /// The number of records before the incorrect line. All of them are correct.
    checked: u64,
    /// The first invalid sequence.
    sequence: u64,
    /// Why the line is not correct.
    reason: String,
}

impl Fault {
    fn into_verification(self) -> ChainVerification {
        ChainVerification {
            valid: false,
            checked: self.checked,
            first_invalid_sequence: Some(self.sequence),
            reason: Some(self.reason),
        }
    }

    fn into_error(self, path: &Path) -> Error {
        Error::Integrity(format!(
            "audit log {} does not verify: first invalid sequence {}: {}",
            path.display(),
            self.sequence,
            self.reason
        ))
    }
}

/// A file in which all lines are correct.
#[derive(Debug)]
struct Verified {
    /// The last record, or `None` if the file is empty.
    head: Option<AuditRecord>,
    /// The number of records.
    records: u64,
    /// The length of the file in bytes.
    len: u64,
    /// The byte offset of the first line of each group of `stride` lines.
    checkpoints: Vec<u64>,
}

/// Reads all lines of `reader` and checks the chain.
///
/// The result is an error only if the read fails. An incorrect line gives `Ok(Err(_))`.
fn scan(reader: impl Read, stride: u64) -> Result<std::result::Result<Verified, Fault>> {
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    let mut state = Verified {
        head: None,
        records: 0,
        len: 0,
        checkpoints: Vec::new(),
    };
    let mut batch: Vec<AuditRecord> = Vec::with_capacity(VERIFY_BATCH);
    let mut lines: u64 = 0;
    let mut offset: u64 = 0;
    let mut line = Vec::new();
    loop {
        line.clear();
        let length = reader
            .read_until(b'\n', &mut line)
            .map_err(|error| Error::Unavailable(format!("cannot read the audit log: {error}")))?
            as u64;
        if length == 0 {
            break;
        }
        let record = if line.pop() == Some(b'\n') {
            decode_line(&line)
        } else {
            Err(format!(
                "the last line is not complete: {length} bytes at byte offset {offset} have \
                 no line end. A write that did not complete can cause this. The log does not \
                 repair the file"
            ))
        };
        match record {
            Ok(record) => {
                if lines.is_multiple_of(stride) {
                    state.checkpoints.push(offset);
                }
                lines += 1;
                offset += length;
                batch.push(record);
                if batch.len() >= VERIFY_BATCH
                    && let Some(fault) = flush(&mut state, &mut batch)?
                {
                    return Ok(Err(fault));
                }
            }
            Err(reason) => {
                if let Some(fault) = flush(&mut state, &mut batch)? {
                    return Ok(Err(fault));
                }
                return Ok(Err(Fault {
                    checked: state.records,
                    sequence: state.records + 1,
                    reason,
                }));
            }
        }
    }
    if let Some(fault) = flush(&mut state, &mut batch)? {
        return Ok(Err(fault));
    }
    state.len = offset;
    Ok(Ok(state))
}

/// Checks the records in `batch` against the records before them.
fn flush(state: &mut Verified, batch: &mut Vec<AuditRecord>) -> Result<Option<Fault>> {
    let report = verify_chain(state.head.as_ref(), batch)?;
    let checked = state.records + report.checked;
    if !report.valid {
        return Ok(Some(Fault {
            checked,
            sequence: report.first_invalid_sequence.unwrap_or(checked + 1),
            reason: report
                .reason
                .unwrap_or_else(|| "the chain is not correct".to_owned()),
        }));
    }
    state.records = checked;
    if let Some(last) = batch.pop() {
        state.head = Some(last);
    }
    batch.clear();
    Ok(None)
}

/// Makes the line of `record`, with the line feed.
fn encode_line(record: &AuditRecord) -> Result<String> {
    let mut line = canonical_json(&serde_json::to_value(record)?);
    line.push('\n');
    Ok(line)
}

/// Reads one line without its line feed. The error tells why the line is not correct.
fn decode_line(line: &[u8]) -> std::result::Result<AuditRecord, String> {
    let text = std::str::from_utf8(line).map_err(|_| "the line is not valid UTF-8".to_owned())?;
    // The message does not include the error text of the parser, because that text can
    // show a part of the record.
    let record: AuditRecord = serde_json::from_str(text).map_err(|error| {
        let problem = match error.classify() {
            serde_json::error::Category::Data => "the line is not an audit record",
            _ => "the line is not valid JSON",
        };
        format!("{problem} (column {})", error.column())
    })?;
    let canonical = serde_json::to_value(&record)
        .map(|value| canonical_json(&value))
        .map_err(|_| "the record cannot be encoded".to_owned())?;
    if canonical != text {
        return Err("the line is not the canonical form of its record".to_owned());
    }
    Ok(record)
}

/// The data that one read needs. The log makes it while it holds the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadPlan {
    path: PathBuf,
    /// The byte offset at which the read starts.
    offset: u64,
    /// The sequence number of the line at `offset`.
    first: u64,
    /// The sequence number of the first record to return.
    from: u64,
    /// The sequence number of the last record in the log.
    last: u64,
    /// The length of the log in bytes.
    end: u64,
    /// The largest number of records to return.
    limit: usize,
}

struct Writer<S> {
    path: PathBuf,
    storage: S,
    head: Option<AuditRecord>,
    len: u64,
    checkpoints: Vec<u64>,
    stride: u64,
    /// Why the log accepts no more records, if that is the case.
    closed: Option<String>,
}

impl<S: Storage> Writer<S> {
    fn new(path: PathBuf, storage: S, verified: Verified, stride: u64) -> Self {
        Self {
            path,
            storage,
            head: verified.head,
            len: verified.len,
            checkpoints: verified.checkpoints,
            stride: stride.max(1),
            closed: None,
        }
    }

    fn append(&mut self, entry: AuditEntry) -> Result<AuditRecord> {
        if let Some(reason) = &self.closed {
            return Err(Error::Integrity(format!(
                "audit log {} accepts no records: {reason}",
                self.path.display()
            )));
        }
        self.check_unchanged()?;
        let record = seal(self.head.as_ref(), entry, Utc::now())?;
        let line = encode_line(&record)?;
        if let Err(error) = self.storage.append(line.as_bytes()) {
            return Err(self.abandon_write(&error));
        }
        if (record.sequence - 1).is_multiple_of(self.stride) {
            self.checkpoints.push(self.len);
        }
        self.len += line.len() as u64;
        self.head = Some(record.clone());
        Ok(record)
    }

    /// Finds a change that a different process made to the file since the last write.
    fn check_unchanged(&mut self) -> Result<()> {
        let unavailable = |error: io::Error| {
            Error::Unavailable(format!(
                "cannot examine audit log {}: {error}",
                self.path.display()
            ))
        };
        let change = if !self.storage.is_at(&self.path).map_err(unavailable)? {
            "the file at this path is not the file that this process opened".to_owned()
        } else {
            let len = self.storage.len().map_err(unavailable)?;
            if len == self.len {
                return Ok(());
            }
            format!(
                "the file has {len} bytes, but this process wrote {} bytes",
                self.len
            )
        };
        let reason = format!("a different process changed the file: {change}");
        let error = Error::Integrity(format!(
            "audit log {} accepts no records: {reason}",
            self.path.display()
        ));
        self.closed = Some(reason);
        Err(error)
    }

    /// Removes the bytes that a failed write left in the file.
    fn abandon_write(&mut self, error: &io::Error) -> Error {
        match self.storage.truncate(self.len) {
            Ok(()) => Error::Unavailable(format!(
                "cannot write to audit log {}: {error}. The log did not keep the record",
                self.path.display()
            )),
            Err(rollback) => {
                let reason = format!(
                    "a write failed ({error}) and the log could not remove the incomplete \
                     record ({rollback}). Open the log again to examine the file"
                );
                let error = Error::Integrity(format!(
                    "audit log {} accepts no records: {reason}",
                    self.path.display()
                ));
                self.closed = Some(reason);
                error
            }
        }
    }

    fn plan(&self, from_sequence: u64, limit: usize) -> Option<ReadPlan> {
        let last = self.head.as_ref()?.sequence;
        let from = from_sequence.max(1);
        if limit == 0 || from > last {
            return None;
        }
        // The read starts one record before `from`, because the chain check of the first
        // record needs the record before it.
        let anchor = (from - 1).max(1);
        let index = (anchor - 1) / self.stride;
        let checkpoint = usize::try_from(index)
            .ok()
            .and_then(|index| self.checkpoints.get(index));
        let (offset, first) = match checkpoint {
            Some(offset) => (*offset, index * self.stride + 1),
            None => (0, 1),
        };
        Some(ReadPlan {
            path: self.path.clone(),
            offset,
            first,
            from,
            last,
            end: self.len,
            limit,
        })
    }
}

fn read_records(plan: &ReadPlan) -> Result<Vec<AuditRecord>> {
    let unavailable = |error: io::Error| {
        Error::Unavailable(format!(
            "cannot read audit log {}: {error}",
            plan.path.display()
        ))
    };
    let mut file = File::open(&plan.path).map_err(unavailable)?;
    file.seek(SeekFrom::Start(plan.offset))
        .map_err(unavailable)?;
    let mut reader = BufReader::new(file.take(plan.end.saturating_sub(plan.offset)));
    let mut anchor = None;
    let mut records = Vec::new();
    let mut line = Vec::new();
    let mut sequence = plan.first;
    while records.len() < plan.limit && sequence <= plan.last {
        line.clear();
        let length = reader.read_until(b'\n', &mut line).map_err(unavailable)?;
        if length == 0 || line.pop() != Some(b'\n') {
            return Err(Error::Integrity(format!(
                "audit log {} ends before sequence {sequence}: a different process changed \
                 the file",
                plan.path.display()
            )));
        }
        if sequence + 1 >= plan.from {
            let record = decode_line(&line).map_err(|reason| {
                Error::Integrity(format!(
                    "audit log {} does not verify: first invalid sequence {sequence}: {reason}",
                    plan.path.display()
                ))
            })?;
            if sequence < plan.from {
                anchor = Some(record);
            } else {
                records.push(record);
            }
        }
        sequence += 1;
    }
    let report = verify_chain(anchor.as_ref(), &records)?;
    if !report.valid {
        return Err(Fault {
            checked: report.checked,
            sequence: report.first_invalid_sequence.unwrap_or(plan.from),
            reason: report
                .reason
                .unwrap_or_else(|| "the chain is not correct".to_owned()),
        }
        .into_error(&plan.path));
    }
    Ok(records)
}

struct Shared {
    writer: Mutex<Writer<File>>,
    /// The lock file. The operating system releases the lock when this handle closes.
    _lock: File,
}

impl Shared {
    fn writer(&self) -> MutexGuard<'_, Writer<File>> {
        self.writer.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An audit log in one append-only JSON Lines file.
///
/// Refer to the [module documentation](self) for the file format and for the changes that
/// the log detects.
///
/// # One writer
///
/// The log holds an exclusive operating system lock on the file `<path>.lock` while it is
/// open. A second [`FileAuditLog::open`] of the same file fails, in this process and in a
/// different process. The log does not remove the lock file.
///
/// On Unix, the log also holds an exclusive lock on the log file itself. Thus a second
/// writer that uses a hard link to the file fails too. The two locks are advisory: they
/// stop a second [`FileAuditLog`], not a program that ignores the locks. The check before
/// each write finds the bytes of such a program.
///
/// # Writes
///
/// [`AuditLog::append`] writes one line and syncs it to the disk before it returns. Appends
/// run one at a time. If a write fails, the log removes the incomplete line and returns
/// [`Error::Unavailable`]; the subsequent append can succeed. If the log cannot remove the
/// incomplete line, it accepts no more records.
///
/// Before each write, the log checks that the file has the length that this process wrote
/// and that the path refers to the same file. If not, a different process changed the file.
/// Then the log returns [`Error::Integrity`] and accepts no more records.
pub struct FileAuditLog {
    path: PathBuf,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for FileAuditLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileAuditLog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileAuditLog {
    /// Opens the log at `path` for append. Makes the file if it does not exist.
    ///
    /// This function reads the full file and checks the chain. It blocks the thread while
    /// it does so.
    ///
    /// # Errors
    ///
    /// - [`Error::Unavailable`] if a different writer has the log open.
    /// - [`Error::Integrity`] if the chain does not verify or the last line is not
    ///   complete. The message gives the first invalid sequence. The function does not
    ///   change the file.
    /// - [`Error::Config`] if the file or its lock file cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_stride(path.as_ref(), CHECKPOINT_STRIDE)
    }

    /// Opens the log that `config` names. Refer to [`FileAuditLog::open`].
    ///
    /// # Errors
    ///
    /// Returns the errors that [`FileAuditLog::open`] gives.
    pub fn from_config(config: &FileAuditLogConfig) -> Result<Self> {
        Self::open(&config.path)
    }

    fn open_with_stride(path: &Path, stride: u64) -> Result<Self> {
        let stride = stride.max(1);
        let path = resolve(path)?;
        let config = |what: &str, error: io::Error| {
            Error::Config(format!(
                "cannot {what} audit log {}: {error}",
                path.display()
            ))
        };
        let lock = acquire_lock(&path)?;
        let file = match OpenOptions::new().append(true).create_new(true).open(&path) {
            Ok(file) => {
                sync_directory(&path).map_err(|error| config("sync the directory of", error))?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
                .append(true)
                .open(&path)
                .map_err(|error| config("open", error))?,
            Err(error) => return Err(config("make", error)),
        };
        lock_log_file(&file, &path)?;
        let reader = File::open(&path).map_err(|error| config("read", error))?;
        let verified = scan(reader, stride)?.map_err(|fault| fault.into_error(&path))?;
        tracing::info!(path = %path.display(), records = verified.records, "opened the audit log");
        Ok(Self {
            shared: Arc::new(Shared {
                writer: Mutex::new(Writer::new(path.clone(), file, verified, stride)),
                _lock: lock,
            }),
            path,
        })
    }

    /// Checks the chain of the log file at `path`. Does not open the log for append.
    ///
    /// Use this function to examine a log that [`FileAuditLog::open`] refuses. It takes no
    /// lock, so the result can be wrong while a writer appends to the file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the file does not exist and [`Error::Unavailable`] if
    /// the file cannot be read. An incorrect chain is not an error: the result has
    /// `valid` set to `false`.
    pub fn verify_file(path: impl AsRef<Path>) -> Result<ChainVerification> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|error| {
            let message = format!("cannot read audit log {}: {error}", path.display());
            if error.kind() == io::ErrorKind::NotFound {
                Error::NotFound(message)
            } else {
                Error::Unavailable(message)
            }
        })?;
        Ok(match scan(file, CHECKPOINT_STRIDE)? {
            Ok(verified) => valid(verified.records),
            Err(fault) => fault.into_verification(),
        })
    }

    /// Returns the path of the log file, with symbolic links resolved.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the last record of the log, or `None` if the log is empty.
    ///
    /// Keep the sequence number and the hash of this record in a different system to find
    /// the removal of the last lines after a restart.
    #[must_use]
    pub fn head(&self) -> Option<AuditRecord> {
        self.shared.writer().head.clone()
    }
}

#[async_trait]
impl AuditLog for FileAuditLog {
    async fn append(&self, entry: AuditEntry) -> Result<AuditRecord> {
        let shared = Arc::clone(&self.shared);
        run_blocking(move || shared.writer().append(entry)).await
    }

    async fn read(&self, from_sequence: u64, limit: usize) -> Result<Vec<AuditRecord>> {
        let shared = Arc::clone(&self.shared);
        run_blocking(move || {
            let plan = shared.writer().plan(from_sequence, limit);
            plan.map_or_else(|| Ok(Vec::new()), |plan| read_records(&plan))
        })
        .await
    }

    async fn verify(&self) -> Result<ChainVerification> {
        let shared = Arc::clone(&self.shared);
        run_blocking(move || verify_open_log(&shared)).await
    }
}

/// Checks the file of an open log against the disk and against the last record in memory.
fn verify_open_log(shared: &Shared) -> Result<ChainVerification> {
    let (path, expected, len, stride) = {
        let writer = shared.writer();
        (
            writer.path.clone(),
            writer.head.clone(),
            writer.len,
            writer.stride,
        )
    };
    let unavailable = |error: io::Error| {
        Error::Unavailable(format!("cannot read audit log {}: {error}", path.display()))
    };
    let expected_records = expected.as_ref().map_or(0, |record| record.sequence);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(invalid(0, 1, "the file does not exist".to_owned()));
        }
        Err(error) => return Err(unavailable(error)),
    };
    // The check stops at the length that this process wrote. A record that this process
    // appends during the check is not a part of the check.
    let verified = match scan(file.take(len), stride)? {
        Ok(verified) => verified,
        Err(fault) => return Ok(fault.into_verification()),
    };
    if verified.records < expected_records {
        return Ok(invalid(
            verified.records,
            verified.records + 1,
            format!(
                "the file ends after record {}, but this process wrote {expected_records} \
                 records",
                verified.records
            ),
        ));
    }
    if verified.head.as_ref().map(|record| &record.hash)
        != expected.as_ref().map(|record| &record.hash)
    {
        return Ok(invalid(
            verified.records.saturating_sub(1),
            verified.records,
            "the last record in the file is not the record that this process wrote last".to_owned(),
        ));
    }
    // No write is in progress while this function holds the lock. Thus the file must have
    // the length that this process wrote.
    let writer = shared.writer();
    let records = writer.head.as_ref().map_or(0, |record| record.sequence);
    if !writer.storage.is_at(&path).map_err(unavailable)? {
        return Ok(invalid(
            records,
            records + 1,
            "the file at this path is not the file that this process opened; new records \
             do not go to this path"
                .to_owned(),
        ));
    }
    let on_disk = fs::metadata(&path).map_err(unavailable)?.len();
    if on_disk > writer.len {
        return Ok(invalid(
            records,
            records + 1,
            format!(
                "the file has {} bytes after the last record that this process wrote",
                on_disk - writer.len
            ),
        ));
    }
    if on_disk < writer.len {
        return Ok(invalid(
            records.saturating_sub(1),
            records,
            format!(
                "the file has {on_disk} bytes, but this process wrote {} bytes",
                writer.len
            ),
        ));
    }
    Ok(valid(verified.records))
}

fn valid(checked: u64) -> ChainVerification {
    ChainVerification {
        valid: true,
        checked,
        first_invalid_sequence: None,
        reason: None,
    }
}

fn invalid(checked: u64, sequence: u64, reason: String) -> ChainVerification {
    Fault {
        checked,
        sequence,
        reason,
    }
    .into_verification()
}

/// Runs file work on a thread that can block.
///
/// Without a Tokio runtime, the work runs on the calling thread.
async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => runtime.spawn_blocking(work).await.map_err(|error| {
            Error::Unavailable(format!("the audit log task did not complete: {error}"))
        })?,
        Err(_) => work(),
    }
}

/// Returns the location of the log file with symbolic links resolved.
///
/// Two paths to one file must give one lock file.
fn resolve(path: &Path) -> Result<PathBuf> {
    let config = |error: io::Error| {
        Error::Config(format!(
            "cannot find the directory of audit log {}: {error}",
            path.display()
        ))
    };
    let Some(name) = path.file_name() else {
        return Err(Error::Config(format!(
            "the audit log path {} has no file name",
            path.display()
        )));
    };
    match fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            Ok(fs::canonicalize(parent).map_err(config)?.join(name))
        }
        Err(error) => Err(config(error)),
    }
}

/// Opens the lock file of the log at `path` and takes the exclusive lock on it.
fn acquire_lock(path: &Path) -> Result<File> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|error| {
            Error::Config(format!(
                "cannot open the lock file {}: {error}",
                lock_path.display()
            ))
        })?;
    take_exclusive_lock(&file, path, &lock_path)?;
    Ok(file)
}

/// Takes the exclusive lock on the log file itself.
///
/// The lock file stops a second writer that uses the same path. This lock also stops a
/// second writer that uses a different name of the same file, for example a hard link.
#[cfg(unix)]
fn lock_log_file(file: &File, path: &Path) -> Result<()> {
    take_exclusive_lock(file, path, path)
}

/// Does nothing. On this system, a lock on the log file stops the reads of the log too.
#[cfg(not(unix))]
fn lock_log_file(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

/// Takes the exclusive operating system lock on `file`. Does not wait for the lock.
///
/// `log` is the path of the audit log. `locked` is the path of `file`.
fn take_exclusive_lock(file: &File, log: &Path, locked: &Path) -> Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(Error::Unavailable(format!(
            "audit log {} has a writer already: the file {} is locked",
            log.display(),
            locked.display()
        ))),
        Err(TryLockError::Error(error)) => Err(Error::Config(format!(
            "cannot lock the file {}: {error}",
            locked.display()
        ))),
    }
}

/// Syncs the directory entry of a new file to the disk.
#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) => File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use aegis_contracts::audit::AuditKind;

    use super::*;

    fn entry(index: usize) -> AuditEntry {
        AuditEntry::new(
            AuditKind::AgentDecision,
            "analyst",
            format!("Decision {index}."),
        )
        .with_payload(serde_json::json!({ "index": index }))
    }

    /// Makes `count` records and the lines of a log that holds them.
    fn chain(count: usize) -> (Vec<AuditRecord>, Vec<String>) {
        let mut records: Vec<AuditRecord> = Vec::with_capacity(count);
        let mut lines = Vec::with_capacity(count);
        for index in 0..count {
            let record = seal(records.last(), entry(index), Utc::now()).unwrap();
            lines.push(encode_line(&record).unwrap());
            records.push(record);
        }
        (records, lines)
    }

    fn fault(lines: &[String]) -> Fault {
        scan(lines.concat().as_bytes(), 100)
            .unwrap()
            .expect_err("the scan must find a fault")
    }

    #[test]
    fn a_long_chain_verifies_and_gives_the_checkpoints() {
        let count = VERIFY_BATCH * 2 + 44;
        let (records, lines) = chain(count);
        let bytes = lines.concat().into_bytes();
        let verified = scan(bytes.as_slice(), 100).unwrap().unwrap();
        assert_eq!(verified.records, count as u64);
        assert_eq!(verified.head.as_ref(), records.last());
        assert_eq!(verified.len, bytes.len() as u64);
        assert_eq!(verified.checkpoints.len(), 6);
        for (index, offset) in verified.checkpoints.iter().enumerate() {
            let start = usize::try_from(*offset).unwrap();
            let line = bytes[start..].split(|byte| *byte == b'\n').next().unwrap();
            let record = decode_line(line).unwrap();
            assert_eq!(record.sequence, index as u64 * 100 + 1);
        }
    }

    #[test]
    fn a_fault_after_the_first_batch_has_the_correct_sequence() {
        let boundary = VERIFY_BATCH;
        let (_, lines) = chain(VERIFY_BATCH * 2 + 44);
        let changed = |index: usize| lines[index].replace("Decision", "Revision");
        let sequence = |index: usize| index as u64 + 1;

        let mut first_of_batch = lines.clone();
        first_of_batch[boundary] = changed(boundary);
        let found = fault(&first_of_batch);
        assert_eq!(
            (found.checked, found.sequence),
            (sequence(boundary) - 1, sequence(boundary))
        );

        let mut last_of_batch = lines.clone();
        last_of_batch[boundary - 1] = changed(boundary - 1);
        let found = fault(&last_of_batch);
        assert_eq!(
            (found.checked, found.sequence),
            (sequence(boundary) - 2, sequence(boundary) - 1)
        );

        let mut removed_at_boundary = lines.clone();
        removed_at_boundary.remove(boundary);
        let found = fault(&removed_at_boundary);
        assert_eq!(
            (found.checked, found.sequence),
            (sequence(boundary) - 1, sequence(boundary) + 1)
        );

        let mut in_last_batch = lines.clone();
        in_last_batch[boundary * 2 + 10] = changed(boundary * 2 + 10);
        let found = fault(&in_last_batch);
        assert_eq!(found.sequence, sequence(boundary * 2 + 10));
        assert_eq!(found.checked, found.sequence - 1);
    }

    #[test]
    fn the_first_of_two_faults_is_the_result() {
        let (_, lines) = chain(VERIFY_BATCH + 100);
        let mut two_faults = lines.clone();
        two_faults[VERIFY_BATCH + 30] = lines[VERIFY_BATCH + 30].replace("Decision", "Revision");
        two_faults[VERIFY_BATCH + 40] = "not a record\n".to_owned();
        let found = fault(&two_faults);
        assert_eq!(found.sequence, VERIFY_BATCH as u64 + 31);
        assert_eq!(found.checked, VERIFY_BATCH as u64 + 30);

        let mut only_bad_line = lines.clone();
        only_bad_line[VERIFY_BATCH + 40] = "not a record\n".to_owned();
        let found = fault(&only_bad_line);
        assert_eq!(found.sequence, VERIFY_BATCH as u64 + 41);
        assert_eq!(found.checked, VERIFY_BATCH as u64 + 40);
    }

    #[test]
    fn a_line_that_is_not_canonical_is_a_fault_when_the_record_is_equal() {
        let (records, lines) = chain(2);
        // The record has no evidence. A different name for the empty field gives an equal
        // record, so only the comparison with the canonical form finds this change.
        let renamed = lines[1].replace(r#""evidence":[]"#, r#""evidencE":[]"#);
        assert_ne!(renamed, lines[1]);
        let parsed: AuditRecord = serde_json::from_str(renamed.trim_end()).unwrap();
        assert_eq!(parsed, records[1]);
        let found = fault(&[lines[0].clone(), renamed]);
        assert_eq!((found.checked, found.sequence), (1, 2));

        let with_space = lines[1].replace(r#""sequence":2"#, r#""sequence": 2"#);
        let found = fault(&[lines[0].clone(), with_space]);
        assert_eq!((found.checked, found.sequence), (1, 2));

        let with_carriage_return = lines[1].replace('\n', "\r\n");
        let found = fault(&[lines[0].clone(), with_carriage_return]);
        assert_eq!((found.checked, found.sequence), (1, 2));

        let empty_line = "\n".to_owned();
        let found = fault(&[lines[0].clone(), lines[1].clone(), empty_line]);
        assert_eq!((found.checked, found.sequence), (2, 3));
    }

    #[test]
    fn a_decode_error_does_not_show_the_record() {
        let line = br#"{"sequence":"secret-value-1","summary":"secret-value-2"}"#;
        let reason = decode_line(line).unwrap_err();
        assert!(reason.contains("not an audit record"), "{reason}");
        assert!(!reason.contains("secret-value"), "{reason}");
        let reason = decode_line(br#"{"summary":"secret-value-3""#).unwrap_err();
        assert!(reason.contains("not valid JSON"), "{reason}");
        assert!(!reason.contains("secret-value"), "{reason}");
        assert_eq!(
            decode_line(&[0xff, 0xfe]).unwrap_err(),
            "the line is not valid UTF-8"
        );
    }

    /// A file that fails on command.
    struct Flaky {
        file: File,
        /// The number of bytes of the next line that go to the file before the write fails.
        fail_after: Option<usize>,
        truncate_fails: bool,
    }

    impl Storage for Flaky {
        fn len(&self) -> io::Result<u64> {
            Storage::len(&self.file)
        }

        fn is_at(&self, path: &Path) -> io::Result<bool> {
            self.file.is_at(path)
        }

        fn append(&mut self, line: &[u8]) -> io::Result<()> {
            match self.fail_after.take() {
                Some(bytes) => {
                    self.file.write_all(&line[..bytes])?;
                    Err(io::Error::other("the disk is full"))
                }
                None => Storage::append(&mut self.file, line),
            }
        }

        fn truncate(&mut self, len: u64) -> io::Result<()> {
            if self.truncate_fails {
                Err(io::Error::other("the file cannot change its length"))
            } else {
                Storage::truncate(&mut self.file, len)
            }
        }
    }

    fn flaky_writer(path: &Path) -> Writer<Flaky> {
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let empty = Verified {
            head: None,
            records: 0,
            len: 0,
            checkpoints: Vec::new(),
        };
        let storage = Flaky {
            file,
            fail_after: None,
            truncate_fails: false,
        };
        Writer::new(path.to_owned(), storage, empty, 2)
    }

    #[test]
    fn a_failed_write_leaves_no_bytes_and_the_next_append_continues_the_chain() {
        for written_before_the_failure in [0, 1, 40] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("audit.jsonl");
            let mut writer = flaky_writer(&path);
            let first = writer.append(entry(0)).unwrap();
            let after_first = fs::read(&path).unwrap();

            writer.storage.fail_after = Some(written_before_the_failure);
            let error = writer.append(entry(1)).unwrap_err();
            assert!(
                matches!(&error, Error::Unavailable(message) if message.contains("the disk is full")),
                "{error:?}"
            );
            assert_eq!(fs::read(&path).unwrap(), after_first);
            assert_eq!(writer.head.as_ref(), Some(&first));

            let second = writer.append(entry(2)).unwrap();
            assert_eq!(second.sequence, 2);
            assert_eq!(second.prev_hash, first.hash);
            assert_eq!(FileAuditLog::verify_file(&path).unwrap(), valid(2));
        }
    }

    #[test]
    fn a_failed_write_that_cannot_be_removed_closes_the_log() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let mut writer = flaky_writer(&path);
        writer.append(entry(0)).unwrap();

        writer.storage.fail_after = Some(40);
        writer.storage.truncate_fails = true;
        let error = writer.append(entry(1)).unwrap_err();
        assert!(matches!(error, Error::Integrity(_)), "{error:?}");
        let with_partial_line = fs::read(&path).unwrap();
        let report = FileAuditLog::verify_file(&path).unwrap();
        assert_eq!(
            (report.valid, report.checked, report.first_invalid_sequence),
            (false, 1, Some(2))
        );

        // The storage works again, but the log does not know what the file holds.
        writer.storage.truncate_fails = false;
        let error = writer.append(entry(2)).unwrap_err();
        assert!(matches!(error, Error::Integrity(_)), "{error:?}");
        assert_eq!(fs::read(&path).unwrap(), with_partial_line);
    }

    #[test]
    fn the_read_plan_starts_at_the_checkpoint_before_the_anchor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let mut writer = flaky_writer(&path);
        let mut ends = vec![0_u64];
        for index in 0..7 {
            writer.append(entry(index)).unwrap();
            ends.push(writer.len);
        }
        // The stride is 2, so the checkpoints are at the sequence numbers 1, 3, 5, and 7.
        assert_eq!(writer.checkpoints, [ends[0], ends[2], ends[4], ends[6]]);

        // (from, offset of the read, sequence number at the offset)
        for (from, offset, first) in [
            (0, ends[0], 1),
            (1, ends[0], 1),
            (2, ends[0], 1),
            (3, ends[0], 1),
            (4, ends[2], 3),
            (5, ends[2], 3),
            (6, ends[4], 5),
            (7, ends[4], 5),
        ] {
            let plan = writer.plan(from, 3).unwrap();
            assert_eq!((plan.offset, plan.first), (offset, first), "from {from}");
            assert_eq!(
                (plan.from, plan.last, plan.end),
                (from.max(1), 7, ends[7]),
                "from {from}"
            );
        }
        assert_eq!(writer.plan(8, 3), None);
        assert_eq!(writer.plan(1, 0), None);
    }

    #[tokio::test]
    async fn reads_from_each_position_return_the_same_records_for_each_stride() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let mut records = Vec::new();
        // The log is opened three times. Each time it has a different stride and gets more
        // records, so the checkpoints come from the scan and from the appends.
        for stride in [1, 3, 4] {
            let log = FileAuditLog::open_with_stride(&path, stride).unwrap();
            for index in 0..4 {
                records.push(log.append(entry(index)).await.unwrap());
            }
            let count = records.len();
            for from in 0..=count + 1 {
                for limit in [1, 2, 5, 50] {
                    let start = from.max(1) - 1;
                    let expected: Vec<AuditRecord> =
                        records.iter().skip(start).take(limit).cloned().collect();
                    let found = log.read(from as u64, limit).await.unwrap();
                    assert_eq!(found, expected, "stride {stride}, read({from}, {limit})");
                }
            }
        }
        assert_eq!(records.len(), 12);
    }
}
