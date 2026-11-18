//! A source connector that replays normalized events from a JSON Lines file.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::time::Instant;

use crate::check_configured_name;

/// The delay that stands for "do not emit" when a replay time is out of range.
const FAR_FUTURE: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 30);

/// How fast a [`FileSource`] emits the events of its file.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ReplayPace {
    /// Emit the events as fast as the consumer reads them.
    #[default]
    Fast,
    /// Keep the time gaps between the events, divided by `speed`.
    ///
    /// With a speed of 1, the replay takes as long as the recording. With a speed of 60,
    /// one recorded minute takes one second.
    Timed {
        /// The factor that divides the recorded time gaps. It must be more than zero.
        speed: f64,
    },
}

/// The configuration of a [`FileSource`].
///
/// ```toml
/// name = "replay"
/// path = "fixtures/artex_style_attack.jsonl"
/// pace = { mode = "timed", speed = 60.0 }
/// batch_size = 100
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSourceConfig {
    /// The name of the connector instance. Events go to `aegis.events.{name}`.
    pub name: String,
    /// The path of the JSON Lines file. Each line holds one normalized event.
    pub path: PathBuf,
    /// How fast the connector emits the events. The default is [`ReplayPace::Fast`].
    #[serde(default)]
    pub pace: ReplayPace,
    /// The largest number of events in one batch. The default is 100.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_batch_size() -> usize {
    100
}

impl FileSourceConfig {
    /// Makes a configuration with the default pace and the default batch size.
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            pace: ReplayPace::default(),
            batch_size: default_batch_size(),
        }
    }

    /// Sets the pace.
    #[must_use]
    pub fn with_pace(mut self, pace: ReplayPace) -> Self {
        self.pace = pace;
        self
    }

    /// Sets the largest number of events in one batch.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }
}

/// A source connector that reads normalized events from a JSON Lines file.
///
/// Each line of the file is one [`Event`] as JSON. The connector ignores empty lines. It
/// emits the events in the order of the file, so write the file in time order. The stream
/// ends at the end of the file.
///
/// The cursor is the number of lines that the caller already has.
///
/// The connector needs no credentials and no network. Use it to run AEGIS offline.
#[derive(Debug, Clone)]
pub struct FileSource {
    config: FileSourceConfig,
}

impl FileSource {
    /// Makes the connector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the name is not valid, the batch size is zero, or the
    /// speed is not a finite number above zero. The function does not open the file. Use
    /// [`check`](SourceConnector::check) for that.
    pub fn new(config: FileSourceConfig) -> Result<Self> {
        check_configured_name(&config.name)?;
        if config.batch_size == 0 {
            return Err(Error::Config(format!(
                "file source {}: batch_size must be more than zero",
                config.name
            )));
        }
        if let ReplayPace::Timed { speed } = config.pace
            && !(speed.is_finite() && speed > 0.0)
        {
            return Err(Error::Config(format!(
                "file source {}: speed must be a finite number above zero",
                config.name
            )));
        }
        Ok(Self { config })
    }

    /// Returns the configuration of the connector.
    #[must_use]
    pub fn config(&self) -> &FileSourceConfig {
        &self.config
    }
}

/// Reads the number of lines that the caller already has from a cursor.
fn line_offset(cursor: Option<&str>) -> Result<usize> {
    cursor.map_or(Ok(0), |text| {
        text.parse().map_err(|_| {
            Error::InvalidInput(format!("file source cursor {text:?} is not a line number"))
        })
    })
}

/// Reads events from a file, one line at a time.
struct EventReader {
    lines: Lines<BufReader<File>>,
    /// The number of lines that the reader consumed.
    line: usize,
    path: PathBuf,
}

impl EventReader {
    /// Opens the file and skips the first `skip` lines.
    async fn open(path: &Path, skip: usize) -> Result<Self> {
        let file = File::open(path).await.map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                Error::NotFound(format!("event file {}", path.display()))
            } else {
                Error::other(format!("open event file {}", path.display()), error)
            }
        })?;
        let mut reader = Self {
            lines: BufReader::new(file).lines(),
            line: 0,
            path: path.to_path_buf(),
        };
        while reader.line < skip {
            if reader.next_line().await?.is_none() {
                break;
            }
        }
        Ok(reader)
    }

    async fn next_line(&mut self) -> Result<Option<String>> {
        match self.lines.next_line().await {
            Ok(Some(text)) => {
                self.line += 1;
                Ok(Some(text))
            }
            Ok(None) => Ok(None),
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                Err(Error::Serialization(format!(
                    "event file {} line {}: the line is not valid UTF-8",
                    self.path.display(),
                    self.line + 1
                )))
            }
            Err(error) => Err(Error::other(
                format!("read event file {}", self.path.display()),
                error,
            )),
        }
    }

    /// Returns the next event, or `None` at the end of the file. Ignores empty lines.
    async fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            let Some(text) = self.next_line().await? else {
                return Ok(None);
            };
            if text.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(&text).map(Some).map_err(|error| {
                Error::Serialization(format!(
                    "event file {} line {}: {error}",
                    self.path.display(),
                    self.line
                ))
            });
        }
    }
}

/// An event that the replay read, with the line number of its line.
struct Pending {
    event: Event,
    line: usize,
}

/// The state of one replay stream.
struct Replay {
    reader: EventReader,
    batch_size: usize,
    pace: ReplayPace,
    /// The event that the replay read but did not emit, because its time is not yet due.
    pending: Option<Pending>,
    /// The instant and the event time at which the timed replay started.
    origin: Option<(Instant, DateTime<Utc>)>,
    /// The error to return after the batch that holds the events before the error.
    failed: Option<Error>,
    ended: bool,
}

impl Replay {
    /// Returns the next event that the replay did not emit yet.
    async fn take_next(&mut self) -> Result<Option<Pending>> {
        if let Some(pending) = self.pending.take() {
            return Ok(Some(pending));
        }
        Ok(self.reader.next_event().await?.map(|event| Pending {
            event,
            line: self.reader.line,
        }))
    }

    /// Returns the instant at which the timed replay must emit an event with `time`.
    fn due(&mut self, time: DateTime<Utc>, speed: f64) -> Instant {
        let (started, first_time) = *self.origin.get_or_insert_with(|| (Instant::now(), time));
        let recorded = time
            .signed_duration_since(first_time)
            .to_std()
            .unwrap_or(Duration::ZERO);
        let scaled =
            Duration::try_from_secs_f64(recorded.as_secs_f64() / speed).unwrap_or(FAR_FUTURE);
        started
            .checked_add(scaled.min(FAR_FUTURE))
            .unwrap_or(started)
    }

    /// Reads the next batch. Returns `None` at the end of the file.
    async fn next_batch(&mut self) -> Option<Result<EventBatch>> {
        if let Some(error) = self.failed.take() {
            self.ended = true;
            return Some(Err(error));
        }
        if self.ended {
            return None;
        }
        let mut events = Vec::new();
        let mut cursor_line = 0;
        while events.len() < self.batch_size {
            let pending = match self.take_next().await {
                Ok(Some(pending)) => pending,
                Ok(None) => {
                    self.ended = true;
                    break;
                }
                Err(error) => {
                    // Emit the events before the error first. Then return the error.
                    self.failed = Some(error);
                    break;
                }
            };
            if let ReplayPace::Timed { speed } = self.pace {
                let due = self.due(pending.event.time, speed);
                if events.is_empty() {
                    tokio::time::sleep_until(due).await;
                } else if due > Instant::now() {
                    self.pending = Some(pending);
                    break;
                }
            }
            cursor_line = pending.line;
            events.push(pending.event);
        }
        if events.is_empty() {
            return self.failed.take().map(|error| {
                self.ended = true;
                Err(error)
            });
        }
        Some(Ok(EventBatch {
            events,
            next_cursor: Some(cursor_line.to_string()),
        }))
    }
}

#[async_trait]
impl SourceConnector for FileSource {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.config.name.clone(),
            vendor: "aegis".to_owned(),
            product: "file".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    async fn check(&self) -> Result<()> {
        EventReader::open(&self.config.path, 0).await.map(|_| ())
    }

    async fn stream(&self, cursor: Option<String>) -> Result<EventStream> {
        let skip = line_offset(cursor.as_deref())?;
        let replay = Replay {
            reader: EventReader::open(&self.config.path, skip).await?,
            batch_size: self.config.batch_size,
            pace: self.config.pace,
            pending: None,
            origin: None,
            failed: None,
            ended: false,
        };
        Ok(Box::pin(futures::stream::unfold(
            replay,
            |mut replay| async move { replay.next_batch().await.map(|batch| (batch, replay)) },
        )))
    }

    async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
        let skip = line_offset(cursor.as_deref())?;
        let mut reader = EventReader::open(&self.config.path, skip).await?;
        let mut events = Vec::new();
        while let Some(event) = reader.next_event().await? {
            if !range.contains(event.time) {
                continue;
            }
            events.push(event);
            if events.len() == self.config.batch_size {
                return Ok(EventBatch {
                    events,
                    next_cursor: Some(reader.line.to_string()),
                });
            }
        }
        Ok(EventBatch {
            events,
            next_cursor: None,
        })
    }
}
