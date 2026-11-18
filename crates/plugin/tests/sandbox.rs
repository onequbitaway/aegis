//! Tests that the sandbox contains a plugin that has a fault.
//!
//! The guests are `faulty-source` and `faulty-action` in `plugins/tests`. Each one does
//! one wrong thing on request. The tests prove that the host turns the fault into an
//! error of that one call and continues to work.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fmt;
use std::future::Future;
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_contracts::action::{ActionConnector, ActionKind, ActionRequest, ActionStatus};
use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{ConnectorInfo, EventBatch, SourceConnector};
use aegis_contracts::{EntityKind, EntityRef, Error};
use aegis_plugin::{HostLimits, PluginHost, PluginKind, PluginManifest};
use futures::StreamExt;
use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::span;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The name that the operator gives to the faulty plugin in these tests.
const NAME: &str = "faulty";
/// The longest time that a test waits for the host.
const PATIENCE: Duration = Duration::from_secs(60);
/// The time limit of one call in the tests that wait for the limit.
///
/// The limit is long enough for a correct call on a busy computer. Thus only a call that
/// does not end gets to the limit.
const SHORT_TIMEOUT: Duration = Duration::from_secs(2);
/// The file that the `probe` mode of the guest tries to write.
const PROBE_FILE: &str = "/tmp/aegis-faulty-source-probe";

/// Makes a host with a small memory limit.
fn strict_host() -> PluginHost {
    PluginHost::new(HostLimits {
        max_memory_bytes: 16 * 1024 * 1024,
        ..HostLimits::default()
    })
    .unwrap()
}

/// Makes a host that stops a call after [`SHORT_TIMEOUT`].
fn short_timeout_host(max_concurrent_calls: usize) -> PluginHost {
    PluginHost::new(HostLimits {
        call_timeout: SHORT_TIMEOUT,
        max_concurrent_calls,
        ..HostLimits::default()
    })
    .unwrap()
}

fn source_manifest(mode: &str) -> PluginManifest {
    let mut manifest = common::manifest(NAME, PluginKind::Source, "faulty-source");
    manifest.poll_interval = Duration::from_millis(10);
    manifest.config.insert("mode".to_owned(), mode.to_owned());
    manifest
}

fn action_manifest(mode: &str) -> PluginManifest {
    let mut manifest = common::manifest(NAME, PluginKind::Action, "faulty-action");
    manifest.config.insert("mode".to_owned(), mode.to_owned());
    manifest
}

async fn faulty_source(host: &PluginHost, mode: &str) -> Arc<dyn SourceConnector> {
    host.load_source(&source_manifest(mode)).await.unwrap()
}

/// Calls `poll` of the plugin one time, through the stream of the contract.
async fn poll_once(source: &Arc<dyn SourceConnector>) -> Result<EventBatch, Error> {
    let mut stream = source.stream(None).await.unwrap();
    tokio::time::timeout(PATIENCE, stream.next())
        .await
        .expect("the host did not return from the plugin call")
        .expect("the stream ended")
}

fn all_time() -> TimeRange {
    TimeRange {
        start: common::time("2000-01-01T00:00:00Z"),
        end: common::time("2100-01-01T00:00:00Z"),
    }
}

/// Returns the context and the cause of an [`Error::Other`] value.
fn other_parts(error: &Error) -> Option<(&str, String)> {
    match error {
        Error::Other { context, source } => Some((context, source.to_string())),
        _ => None,
    }
}

/// Runs `scenario` on a runtime with one thread and returns its result.
///
/// A plugin that blocks the runtime thread also stops each timer of that runtime. Thus a
/// different thread is the watchdog: it makes the test fail when the scenario does not
/// end in [`PATIENCE`].
fn on_one_thread_with_watchdog<S, F>(scenario: S) -> F::Output
where
    S: FnOnce() -> F + Send + 'static,
    F: Future,
    F::Output: Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // The watchdog does not listen after it gave up. Then this result has no reader.
        let _ = sender.send(runtime.block_on(scenario()));
    });
    match receiver.recv_timeout(PATIENCE) {
        Ok(output) => output,
        Err(RecvTimeoutError::Timeout) => {
            panic!("the scenario did not end in {PATIENCE:?}: a plugin blocked the runtime thread")
        }
        // The scenario panicked. Show its message.
        Err(RecvTimeoutError::Disconnected) => match worker.join() {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(()) => panic!("the scenario ended without a result"),
        },
    }
}

fn tag_request() -> ActionRequest {
    ActionRequest::new(
        ActionKind::Tag,
        EntityRef::new(EntityKind::Host, "host-1"),
        "responder",
        "Test.",
    )
}

#[test]
fn a_guest_that_loops_forever_returns_a_timeout_and_does_not_hang_the_host() {
    let (error, elapsed, later) = on_one_thread_with_watchdog(|| async {
        let host = short_timeout_host(4);
        let source = faulty_source(&host, "loop").await;
        let started = Instant::now();
        let error = poll_once(&source).await.unwrap_err();
        let elapsed = started.elapsed();
        // The plugin is usable after the timeout: each call has a new instance.
        let later = source.fetch(all_time(), None).await.unwrap();
        (error, elapsed, later)
    });

    assert!(
        matches!(&error, Error::Timeout(message)
            if message == "plugin faulty: `poll` did not complete in 2s"),
        "{error:?}"
    );
    assert!(error.is_retryable());
    assert!(elapsed >= SHORT_TIMEOUT, "{elapsed:?}");
    assert!(elapsed < PATIENCE, "{elapsed:?}");
    assert_eq!(later.events, Vec::new());
}

#[test]
fn a_guest_that_loops_does_not_block_other_work_on_the_same_thread() {
    // The scenario has one runtime thread. The healthy plugin can only run if the loop
    // gives control back to the runtime.
    let (loop_in_progress, stopped) = on_one_thread_with_watchdog(|| async {
        let host = PluginHost::new(HostLimits {
            call_timeout: Duration::from_secs(20),
            ..HostLimits::default()
        })
        .unwrap();
        let looping = faulty_source(&host, "loop").await;
        let healthy = host
            .load_source(&common::manifest(
                "example",
                PluginKind::Source,
                "example-source",
            ))
            .await
            .unwrap();

        let stuck = tokio::spawn(async move { poll_once(&looping).await });
        // Let the loop start before the healthy plugin runs.
        tokio::task::yield_now().await;
        for _ in 0..20 {
            healthy.check().await.unwrap();
        }
        let loop_in_progress = !stuck.is_finished();
        stuck.abort();
        (loop_in_progress, stuck.await)
    });

    // The healthy calls ran between the time slices of the loop. They did not wait for
    // the time limit to stop it.
    assert!(
        loop_in_progress,
        "the healthy plugin had to wait for the end of the loop"
    );
    assert!(stopped.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn a_guest_that_sleeps_returns_a_timeout() {
    let host = short_timeout_host(4);
    let source = faulty_source(&host, "sleep").await;
    let started = Instant::now();

    // The guest sleeps for one hour.
    let error = poll_once(&source).await.unwrap_err();

    assert!(
        matches!(&error, Error::Timeout(message)
            if message == "plugin faulty: `poll` did not complete in 2s"),
        "{error:?}"
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= SHORT_TIMEOUT, "{elapsed:?}");
    assert!(elapsed < PATIENCE, "{elapsed:?}");
}

#[tokio::test]
async fn a_plugin_runs_one_call_at_a_time_and_a_dropped_call_stops() {
    let host = PluginHost::new(HostLimits {
        call_timeout: Duration::from_secs(60),
        max_concurrent_calls: 1,
        ..HostLimits::default()
    })
    .unwrap();
    let source = faulty_source(&host, "loop").await;

    // One poll starts the first call. It gets the only call position and does not end.
    let mut stream = source.stream(None).await.unwrap();
    assert!(futures::poll!(stream.next()).is_pending());

    // The second call is short, but it cannot start while the first call has the position.
    let mut second = Box::pin(source.fetch(all_time(), None));
    let waited = tokio::time::timeout(Duration::from_millis(200), &mut second).await;
    assert!(
        waited.is_err(),
        "the second call ran at the same time as the first call"
    );

    // The caller drops the first call. Its plugin code stops and gives up the position.
    drop(stream);
    let batch = tokio::time::timeout(PATIENCE, second)
        .await
        .expect("the dropped call did not release its position")
        .unwrap();
    assert_eq!(batch.events, Vec::new());
}

/// The clock of this test moves only when each task waits for a timer. Then it jumps to
/// the time of the next timer, which is the deadline of the second call.
#[tokio::test(start_paused = true)]
async fn a_call_that_gets_no_position_before_its_deadline_returns_a_timeout() {
    let host = short_timeout_host(1);
    let source = faulty_source(&host, "loop").await;

    // One poll starts the first call. It gets the only call position and does not end.
    let mut stream = source.stream(None).await.unwrap();
    assert!(futures::poll!(stream.next()).is_pending());

    let started = tokio::time::Instant::now();
    let error = source.fetch(all_time(), None).await.unwrap_err();

    assert!(
        matches!(&error, Error::Timeout(message)
            if message == "plugin faulty: `fetch` did not start in 2s, because 1 other calls are in progress"),
        "{error:?}"
    );
    assert!(error.is_retryable());
    assert_eq!(started.elapsed(), SHORT_TIMEOUT);
}

#[tokio::test]
async fn a_guest_that_traps_returns_an_error_and_the_host_continues() {
    let host = strict_host();
    let source = faulty_source(&host, "trap").await;

    let error = poll_once(&source).await.unwrap_err();

    assert_eq!(
        other_parts(&error),
        Some((
            "plugin faulty: `poll` failed in the sandbox",
            "wasm trap: wasm `unreachable` instruction executed".to_owned()
        )),
        "{error:?}"
    );
    assert!(!error.is_retryable());
    // The same connector and the same host work after the trap.
    let batch = source.fetch(all_time(), None).await.unwrap();
    assert_eq!(batch.events, Vec::new());
    source.check().await.unwrap();
}

#[tokio::test]
async fn a_guest_that_allocates_past_the_memory_limit_fails_cleanly() {
    let host = strict_host();
    let source = faulty_source(&host, "alloc").await;

    let error = poll_once(&source).await.unwrap_err();

    assert!(
        matches!(&error, Error::BudgetExceeded(message)
            if message == "plugin faulty: `poll` needs more memory than the limit of 16777216 bytes"),
        "{error:?}"
    );
    let batch = source.fetch(all_time(), None).await.unwrap();
    assert_eq!(batch.events, Vec::new());
}

#[tokio::test]
async fn a_component_that_starts_with_more_memory_than_the_limit_does_not_load() {
    // One WebAssembly page is 64 KiB. A Rust guest starts with more than one page.
    let host = PluginHost::new(HostLimits {
        max_memory_bytes: 64 * 1024,
        ..HostLimits::default()
    })
    .unwrap();

    let error = host
        .load_source(&source_manifest(""))
        .await
        .err()
        .expect("the plugin loaded with too little memory");

    assert!(
        matches!(&error, Error::BudgetExceeded(message) if message.contains("65536 bytes")),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_guest_result_over_the_transfer_limit_fails_cleanly() {
    let host = PluginHost::new(HostLimits {
        max_transfer_bytes: 64 * 1024,
        ..HostLimits::default()
    })
    .unwrap();
    let mut manifest = source_manifest("big-output");
    manifest
        .config
        .insert("output_bytes".to_owned(), "65537".to_owned());
    let source = host.load_source(&manifest).await.unwrap();

    let error = poll_once(&source).await.unwrap_err();

    // The host stops the transfer before it copies the text out of the plugin.
    assert_eq!(
        other_parts(&error),
        Some((
            "plugin faulty: `poll` failed in the sandbox",
            "too much data is being copied between the host and the guest: \
             fuel allocated for hostcalls has been exhausted"
                .to_owned()
        )),
        "{error:?}"
    );

    // Text of the largest permitted size goes through. It is not JSON, thus the decoder
    // refuses it.
    manifest
        .config
        .insert("output_bytes".to_owned(), "65536".to_owned());
    let source = host.load_source(&manifest).await.unwrap();
    let error = poll_once(&source).await.unwrap_err();
    assert!(matches!(error, Error::Serialization(_)), "{error:?}");
}

#[tokio::test]
async fn malformed_json_from_a_guest_is_a_serialization_error_that_names_the_plugin() {
    let host = strict_host();

    let error = poll_once(&faulty_source(&host, "bad-json").await)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message)
        if message.starts_with(
            "plugin faulty: `poll` did not return the JSON form of EventBatch: "
        )),
        "{error:?}"
    );

    // This text is JSON, but an event in it has the wrong shape.
    let error = poll_once(&faulty_source(&host, "wrong-shape").await)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message)
            if message.starts_with("plugin faulty: `poll` did not return the JSON form of EventBatch: ")),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_guest_with_a_malformed_identity_does_not_load() {
    let host = strict_host();

    let error = host
        .load_source(&source_manifest("bad-info"))
        .await
        .err()
        .expect("the plugin loaded with a malformed identity");

    assert!(
        matches!(&error, Error::Serialization(message)
        if message.starts_with(
            "plugin faulty: `info` did not return the JSON form of ConnectorInfo: "
        )),
        "{error:?}"
    );
}

#[tokio::test]
async fn the_host_cleans_and_limits_the_identity_labels_of_a_guest() {
    let host = strict_host();

    let source = faulty_source(&host, "odd-info").await;

    // The guest gave a vendor of 5000 characters and a product with a line feed.
    assert_eq!(
        source.info(),
        ConnectorInfo {
            name: NAME.to_owned(),
            vendor: format!("{}...", "v".repeat(1024)),
            product: "faulty ERROR forged line".to_owned(),
            version: "0.0.0".to_owned(),
        }
    );
}

#[tokio::test]
async fn each_guest_error_maps_to_the_contract_error_of_the_same_kind() {
    let host = strict_host();
    let source = faulty_source(&host, "").await;
    let text = "plugin faulty: The faulty source returns this error on request.";
    type Check = fn(&Error) -> Option<&str>;
    let cases: [(&str, bool, Check); 7] = [
        ("invalid-input", false, |error| match error {
            Error::InvalidInput(message) => Some(message),
            _ => None,
        }),
        ("not-found", false, |error| match error {
            Error::NotFound(message) => Some(message),
            _ => None,
        }),
        ("unauthorized", false, |error| match error {
            Error::Unauthorized(message) => Some(message),
            _ => None,
        }),
        ("unsupported", false, |error| match error {
            Error::Unsupported(message) => Some(message),
            _ => None,
        }),
        ("unavailable", true, |error| match error {
            Error::Unavailable(message) => Some(message),
            _ => None,
        }),
        ("rate-limited", true, |error| match error {
            Error::RateLimited(message) => Some(message),
            _ => None,
        }),
        ("timeout", true, |error| match error {
            Error::Timeout(message) => Some(message),
            _ => None,
        }),
    ];
    for (kind, retryable, message_of) in cases {
        let error = source
            .fetch(all_time(), Some(kind.to_owned()))
            .await
            .unwrap_err();
        assert_eq!(message_of(&error), Some(text), "{kind}: {error:?}");
        assert_eq!(error.is_retryable(), retryable, "{kind}");
    }

    let error = source
        .fetch(all_time(), Some("other".to_owned()))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Other { context, .. } if context == "plugin faulty"),
        "{error:?}"
    );
    assert_eq!(error.to_string(), text);
}

#[tokio::test]
async fn a_guest_has_no_environment_no_filesystem_and_no_sockets() {
    let _ = std::fs::remove_file(PROBE_FILE);
    // The guest tries to connect to this listener. The listener is on this computer.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut manifest = source_manifest("probe");
    manifest.config.insert(
        "probe_address".to_owned(),
        listener.local_addr().unwrap().to_string(),
    );
    // The process of the test has environment variables and can read `/`.
    assert!(std::env::vars_os().count() > 0);
    assert!(std::fs::read_dir("/").is_ok());
    let source = PluginHost::new(HostLimits::default())
        .unwrap()
        .load_source(&manifest)
        .await
        .unwrap();

    let batch = poll_once(&source).await.unwrap();

    assert_eq!(batch.events.len(), 1);
    let report = serde_json::to_value(&batch.events[0].attributes).unwrap();
    assert_eq!(
        report,
        json!({
            "env_count": 0,
            "args_count": 0,
            "directory_listed": false,
            "file_read": false,
            "file_written": false,
            "tcp_connected": false,
            "udp_bound": false,
            "name_resolved": false,
        })
    );
    assert!(!Path::new(PROBE_FILE).exists());
    let accepted = listener.accept();
    assert!(
        matches!(&accepted, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "a connection reached the listener: {accepted:?}"
    );
}

#[tokio::test]
async fn a_guest_cannot_emit_an_event_in_the_name_of_a_different_connector() {
    let host = strict_host();
    let source = faulty_source(&host, "spoof").await;

    let batch = poll_once(&source).await.unwrap();

    assert_eq!(batch.events.len(), 1);
    // The guest wrote `entra-prod`. The host wrote the name of the manifest.
    assert_eq!(batch.events[0].source.connector, NAME);
}

/// One log event that the host wrote for a plugin.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct LogLine {
    plugin: String,
    message: String,
}

impl Visit for LogLine {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "plugin" {
            value.clone_into(&mut self.plugin);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

/// A `tracing` subscriber that keeps the log events of the plugin host.
struct Capture(Arc<Mutex<Vec<LogLine>>>);

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("aegis_plugin")
    }

    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = LogLine::default();
        event.record(&mut line);
        self.0.lock().unwrap().push(line);
    }

    fn enter(&self, _: &span::Id) {}

    fn exit(&self, _: &span::Id) {}
}

#[tokio::test]
async fn a_guest_that_floods_the_log_gets_only_its_budget_of_log_lines() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(Capture(Arc::clone(&lines)));
    let host = PluginHost::new(HostLimits {
        max_log_messages_per_call: 7,
        ..HostLimits::default()
    })
    .unwrap();
    let source = faulty_source(&host, "log-flood").await;

    // The guest writes 10 000 messages in each call.
    poll_once(&source).await.unwrap();

    // The host writes the messages in the budget, and one line for the end of the budget.
    let written = lines.lock().unwrap().clone();
    assert_eq!(written.len(), 8);
    assert!(written.iter().all(|line| line.plugin == NAME));
    let messages: Vec<&str> = written.iter().map(|line| line.message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "Flood message 0.",
            "Flood message 1.",
            "Flood message 2.",
            "Flood message 3.",
            "Flood message 4.",
            "Flood message 5.",
            "Flood message 6.",
            "The plugin wrote more than 7 log messages in one call. The host drops the remainder.",
        ]
    );

    // Each call has its own budget.
    poll_once(&source).await.unwrap();
    assert_eq!(lines.lock().unwrap().len(), 16);
}

#[tokio::test]
async fn a_host_with_a_log_limit_of_zero_writes_no_line_for_a_guest() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(Capture(Arc::clone(&lines)));
    let host = PluginHost::new(HostLimits {
        max_log_messages_per_call: 0,
        ..HostLimits::default()
    })
    .unwrap();
    let source = faulty_source(&host, "log-flood").await;

    poll_once(&source).await.unwrap();

    assert_eq!(lines.lock().unwrap().clone(), Vec::new());
}

/// Returns the messages that the host wrote for the plugin [`NAME`] with `prefix`.
fn messages_with(lines: &Mutex<Vec<LogLine>>, prefix: &str) -> Vec<String> {
    lines
        .lock()
        .unwrap()
        .iter()
        .filter(|line| line.plugin == NAME && line.message.starts_with(prefix))
        .map(|line| line.message.clone())
        .collect()
}

#[tokio::test]
async fn a_guest_cannot_hold_more_host_resources_than_the_limit() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(Capture(Arc::clone(&lines)));
    let host = PluginHost::new(HostLimits {
        max_log_messages_per_call: 100_000,
        ..HostLimits::default()
    })
    .unwrap();
    let source = faulty_source(&host, "hold-timers").await;

    // The guest makes timers without end. It writes one log message for each timer.
    let error = poll_once(&source).await.unwrap_err();

    assert_eq!(
        other_parts(&error),
        Some((
            "plugin faulty: `poll` failed in the sandbox",
            "resource table has no free keys".to_owned()
        )),
        "{error:?}"
    );
    // The limit is 1024 host resources. One timer uses two: the timer and its pollable.
    let held = messages_with(&lines, "The plugin holds ");
    assert_eq!(held.len(), 512);
    assert_eq!(
        held.last().map(String::as_str),
        Some("The plugin holds 512 timers.")
    );
    // The host continues to work.
    let batch = source.fetch(all_time(), None).await.unwrap();
    assert_eq!(batch.events, Vec::new());
}

#[tokio::test]
async fn a_guest_cannot_make_the_host_allocate_a_large_block_of_random_bytes() {
    let host = strict_host();
    let mut manifest = source_manifest("random");

    // One WASI call can get 1 MiB of random bytes.
    manifest
        .config
        .insert("random_bytes".to_owned(), "1048576".to_owned());
    let source = host.load_source(&manifest).await.unwrap();
    let batch = poll_once(&source).await.unwrap();
    assert_eq!(batch.events.len(), 1);
    assert_eq!(
        serde_json::to_value(&batch.events[0].attributes).unwrap(),
        json!({ "received": 1_048_576 })
    );

    // The host allocates the bytes outside the memory of the plugin. It refuses more.
    manifest
        .config
        .insert("random_bytes".to_owned(), "1048577".to_owned());
    let source = host.load_source(&manifest).await.unwrap();
    let error = poll_once(&source).await.unwrap_err();
    assert_eq!(
        other_parts(&error),
        Some((
            "plugin faulty: `poll` failed in the sandbox",
            "requested len 1048577 exceeds limit 1048576".to_owned()
        )),
        "{error:?}"
    );
}

/// The start of the log line that the host writes for a failed HTTP request of a plugin.
const HTTP_FAILURE: &str = "The host did not complete an HTTP request of the plugin: ";

#[tokio::test]
async fn a_guest_that_floods_refused_http_requests_gets_only_its_budget_of_checks() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(Capture(Arc::clone(&lines)));
    let server = MockServer::start().await;
    let host = PluginHost::new(HostLimits {
        max_http_requests_per_call: 3,
        ..HostLimits::default()
    })
    .unwrap();
    // The manifest has no permitted hosts. The host refuses each request.
    let mut manifest = source_manifest("http-flood");
    manifest
        .config
        .insert("flood_url".to_owned(), format!("{}/flood", server.uri()));
    let source = host.load_source(&manifest).await.unwrap();

    // The guest sends 1000 requests in one call.
    let batch = poll_once(&source).await.unwrap();

    assert_eq!(batch.events.len(), 1);
    assert_eq!(
        serde_json::to_value(&batch.events[0].attributes).unwrap(),
        json!({ "sent": 0, "unauthorized": 3, "other_errors": 997 })
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
    // The host writes one line for each refusal in the budget, and one line for the end
    // of the budget. The 996 refusals after that write nothing.
    let refused = format!(
        "{HTTP_FAILURE}the destination {} is not in allowed_hosts.",
        server.address()
    );
    assert_eq!(
        messages_with(&lines, HTTP_FAILURE),
        [
            refused.clone(),
            refused.clone(),
            refused,
            format!("{HTTP_FAILURE}the plugin made more than 3 HTTP requests in one call."),
        ]
    );
}

#[tokio::test]
async fn a_long_host_name_in_a_refused_request_does_not_make_a_long_log_line() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(Capture(Arc::clone(&lines)));
    let host = PluginHost::new(HostLimits {
        max_http_requests_per_call: 1,
        ..HostLimits::default()
    })
    .unwrap();
    let mut manifest = source_manifest("http-flood");
    let long_name = "a".repeat(100_000);
    manifest.config.insert(
        "flood_url".to_owned(),
        format!("https://{long_name}.example.com/"),
    );
    let source = host.load_source(&manifest).await.unwrap();

    poll_once(&source).await.unwrap();

    // The host keeps 1024 characters of the refusal and marks the cut.
    let refusal = format!("the destination {long_name}");
    let kept: String = refusal.chars().take(1024).collect();
    assert_eq!(
        messages_with(&lines, HTTP_FAILURE),
        [
            format!("{HTTP_FAILURE}{kept}...."),
            format!("{HTTP_FAILURE}the plugin made more than 1 HTTP requests in one call."),
        ]
    );
}

#[tokio::test]
async fn a_guest_that_floods_permitted_http_requests_sends_only_its_budget() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let host = PluginHost::new(HostLimits {
        max_http_requests_per_call: 3,
        ..HostLimits::default()
    })
    .unwrap();
    let mut manifest = source_manifest("http-flood");
    manifest.allowed_hosts = vec![server.address().to_string()];
    manifest
        .config
        .insert("flood_url".to_owned(), format!("{}/flood", server.uri()));
    let source = host.load_source(&manifest).await.unwrap();

    let batch = poll_once(&source).await.unwrap();

    assert_eq!(batch.events.len(), 1);
    assert_eq!(
        serde_json::to_value(&batch.events[0].attributes).unwrap(),
        json!({ "sent": 3, "unauthorized": 0, "other_errors": 997 })
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
    // Each call has its own budget.
    poll_once(&source).await.unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 6);
}

#[tokio::test]
async fn malformed_json_from_an_action_guest_is_a_serialization_error() {
    let host = strict_host();

    let action = host
        .load_action(&action_manifest("bad-json"))
        .await
        .unwrap();
    let error = action.execute(&tag_request()).await.unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message)
        if message.starts_with(
            "plugin faulty: `execute` did not return the JSON form of ActionOutcome: "
        )),
        "{error:?}"
    );

    let action = host
        .load_action(&action_manifest("wrong-shape"))
        .await
        .unwrap();
    let error = action.execute(&tag_request()).await.unwrap_err();
    assert!(
        matches!(&error, Error::Serialization(message) if message.contains("ActionOutcome")),
        "{error:?}"
    );

    let error = host
        .load_action(&action_manifest("bad-kinds"))
        .await
        .err()
        .expect("the plugin loaded with a malformed list of action types");
    assert!(
        matches!(&error, Error::Serialization(message)
        if message.starts_with(
            "plugin faulty: `supported-actions` did not return the JSON form of a list of ActionKind: "
        )),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_action_guest_cannot_answer_for_a_different_action_or_connector() {
    let host = strict_host();
    let action = host
        .load_action(&action_manifest("foreign-outcome"))
        .await
        .unwrap();
    let request = tag_request();

    let outcome = action.execute(&request).await.unwrap();

    // The guest wrote a different action identifier and the connector `entra-prod`.
    assert_eq!(outcome.action_id, request.id);
    assert_eq!(outcome.connector, NAME);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
}

#[tokio::test]
async fn an_action_guest_that_reports_a_change_for_a_dry_run_gets_an_error() {
    let host = strict_host();
    // With no mode, this guest reports `succeeded` and does not look at `dry_run`.
    let action = host.load_action(&action_manifest("")).await.unwrap();
    let mut request = tag_request();
    request.dry_run = true;

    for result in [
        action.execute(&request).await,
        action.revert(&request).await,
    ] {
        let error = result.unwrap_err();
        let (context, cause) = other_parts(&error).expect("an `Error::Other` value");
        assert!(
            context == "plugin faulty: `execute` broke the dry-run rule"
                || context == "plugin faulty: `revert` broke the dry-run rule",
            "{context}"
        );
        assert_eq!(
            cause,
            "the request was a dry run, but the plugin reports that it changed the target"
        );
    }

    // A guest that reports a simulation for a dry run obeys the rule.
    let action = host
        .load_action(&action_manifest("simulated"))
        .await
        .unwrap();
    let outcome = action.execute(&request).await.unwrap();
    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert_eq!(outcome.message, "Would execute.");
}

#[tokio::test]
async fn an_action_guest_that_reports_a_simulation_for_a_real_request_gets_an_error() {
    let host = strict_host();
    let action = host
        .load_action(&action_manifest("simulated"))
        .await
        .unwrap();

    let error = action.execute(&tag_request()).await.unwrap_err();

    assert_eq!(
        other_parts(&error),
        Some((
            "plugin faulty: `execute` broke the dry-run rule",
            "the request was not a dry run, but the plugin reports a simulation".to_owned()
        )),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_action_guest_can_declare_custom_actions_and_revert() {
    let host = strict_host();
    let action: Arc<dyn ActionConnector> = host.load_action(&action_manifest("")).await.unwrap();
    assert_eq!(
        action.supported_actions(),
        [ActionKind::Tag, ActionKind::Custom("probe".to_owned())]
    );
    let request = tag_request();

    let executed = action.execute(&request).await.unwrap();
    let reverted = action.revert(&request).await.unwrap();

    assert_eq!(executed.message, "Executed.");
    assert_eq!(reverted.message, "Reverted.");
    assert_eq!(reverted.action_id, request.id);
    assert!(reverted.reversible);
    assert_eq!(reverted.completed_at, common::time("2026-01-02T03:00:00Z"));
}
