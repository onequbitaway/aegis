//! Fakes that inject faults for the tests of the ingestion runner.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aegis_contracts::bus::{BusStream, MessageBus};
use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use aegis_ingest::{CheckpointStore, MemoryCheckpointStore};
use aegis_testkit::{MemoryBus, StaticSource};
use async_trait::async_trait;
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

/// Returns the path of the recorded attack log in the repository.
pub fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/artex_style_attack.jsonl")
}

/// Decodes all events that the bus holds for `subject`, in the order of arrival.
pub fn published_events(bus: &MemoryBus, subject: &str) -> Vec<Event> {
    bus.published_to(subject)
        .iter()
        .map(|message| message.decode::<Event>().unwrap())
        .collect()
}

/// A source that serves a fixed list of events and fails when the test tells it to.
pub struct FaultySource {
    inner: StaticSource,
    /// Errors that `stream` returns, one for each call, before it opens the stream.
    open_errors: Mutex<VecDeque<Error>>,
    /// For each opened stream: the number of good batches, and the error after them.
    stream_errors: Mutex<VecDeque<(usize, Error)>>,
    /// Errors that `fetch` returns, one for each call, before it reads a page.
    fetch_errors: Mutex<VecDeque<Error>>,
    /// The cursor of each `stream` call.
    opened: Mutex<Vec<Option<String>>>,
    /// With `true`, a stream does not end after its last batch.
    endless: bool,
}

impl FaultySource {
    pub fn new(name: &str, events: Vec<Event>, page_size: usize) -> Self {
        Self {
            inner: StaticSource::new(name, events).with_page_size(page_size),
            open_errors: Mutex::default(),
            stream_errors: Mutex::default(),
            fetch_errors: Mutex::default(),
            opened: Mutex::default(),
            endless: false,
        }
    }

    /// Makes each stream stay open after its last batch.
    pub fn endless(mut self) -> Self {
        self.endless = true;
        self
    }

    /// Makes the next `stream` calls fail with these errors, one for each call.
    pub fn fail_open(self, errors: impl IntoIterator<Item = Error>) -> Self {
        self.open_errors.lock().unwrap().extend(errors);
        self
    }

    /// Makes the next opened stream fail with `error` after `batches` good batches.
    pub fn fail_stream_after(self, batches: usize, error: Error) -> Self {
        self.stream_errors
            .lock()
            .unwrap()
            .push_back((batches, error));
        self
    }

    /// Makes the next `fetch` calls fail with these errors, one for each call.
    pub fn fail_fetch(self, errors: impl IntoIterator<Item = Error>) -> Self {
        self.fetch_errors.lock().unwrap().extend(errors);
        self
    }

    /// Returns the cursor of each `stream` call, in order.
    pub fn opened(&self) -> Vec<Option<String>> {
        self.opened.lock().unwrap().clone()
    }
}

#[async_trait]
impl SourceConnector for FaultySource {
    fn info(&self) -> ConnectorInfo {
        self.inner.info()
    }

    async fn check(&self) -> Result<()> {
        self.inner.check().await
    }

    async fn stream(&self, cursor: Option<String>) -> Result<EventStream> {
        self.opened.lock().unwrap().push(cursor.clone());
        if let Some(error) = self.open_errors.lock().unwrap().pop_front() {
            return Err(error);
        }
        let stream = self.inner.stream(cursor).await?;
        let stream: EventStream = match self.stream_errors.lock().unwrap().pop_front() {
            Some((batches, error)) => Box::pin(
                stream
                    .take(batches)
                    .chain(futures::stream::once(async move { Err(error) })),
            ),
            None => stream,
        };
        if self.endless {
            Ok(Box::pin(stream.chain(futures::stream::pending())))
        } else {
            Ok(stream)
        }
    }

    async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
        if let Some(error) = self.fetch_errors.lock().unwrap().pop_front() {
            return Err(error);
        }
        self.inner.fetch(range, cursor).await
    }
}

/// A bus that keeps the messages in a [`MemoryBus`] and fails when the test tells it to.
#[derive(Default)]
pub struct FaultyBus {
    pub inner: MemoryBus,
    /// The number of `publish` calls.
    attempts: AtomicUsize,
    /// The error for the `publish` call with this number. The first call is number 0.
    errors: Mutex<HashMap<usize, Error>>,
    /// Fires the token when the bus holds this number of messages.
    cancel_at: Mutex<Option<(usize, CancellationToken)>>,
}

impl FaultyBus {
    /// Makes the `publish` call with the number `attempt` fail with `error`.
    pub fn fail_attempt(self, attempt: usize, error: Error) -> Self {
        self.errors.lock().unwrap().insert(attempt, error);
        self
    }

    /// Fires `token` when the bus holds `count` messages.
    pub fn cancel_at(self, count: usize, token: CancellationToken) -> Self {
        *self.cancel_at.lock().unwrap() = Some((count, token));
        self
    }
}

#[async_trait]
impl MessageBus for FaultyBus {
    async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.errors.lock().unwrap().remove(&attempt) {
            return Err(error);
        }
        self.inner.publish(subject, payload).await?;
        if let Some((count, token)) = self.cancel_at.lock().unwrap().as_ref()
            && self.inner.published().len() == *count
        {
            token.cancel();
        }
        Ok(())
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        self.inner.subscribe(pattern, durable).await
    }
}

/// A checkpoint store that keeps the cursors in memory and fails when the test tells it to.
#[derive(Default)]
pub struct FaultyStore {
    pub inner: Arc<MemoryCheckpointStore>,
    saves: AtomicUsize,
    /// The error for the `save` call with this number. The first call is number 0.
    save_errors: Mutex<HashMap<usize, Error>>,
    /// Errors that `load` returns, one for each call.
    load_errors: Mutex<VecDeque<Error>>,
}

impl FaultyStore {
    /// Makes the `save` call with the number `call` fail with `error`.
    pub fn fail_save(self, call: usize, error: Error) -> Self {
        self.save_errors.lock().unwrap().insert(call, error);
        self
    }

    /// Makes the next `load` calls fail with these errors, one for each call.
    pub fn fail_load(self, errors: impl IntoIterator<Item = Error>) -> Self {
        self.load_errors.lock().unwrap().extend(errors);
        self
    }
}

#[async_trait]
impl CheckpointStore for FaultyStore {
    async fn load(&self, name: &str) -> Result<Option<String>> {
        if let Some(error) = self.load_errors.lock().unwrap().pop_front() {
            return Err(error);
        }
        self.inner.load(name).await
    }

    async fn save(&self, name: &str, cursor: &str) -> Result<()> {
        let call = self.saves.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.save_errors.lock().unwrap().remove(&call) {
            return Err(error);
        }
        self.inner.save(name, cursor).await
    }
}
