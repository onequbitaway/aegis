//! The tests of the NATS bus against a real NATS server.
//!
//! The `docker-tests` feature enables these tests. They use the server in the environment
//! variable `AEGIS_TEST_NATS_URL`, or they start a disposable server with Docker. The tests
//! that restart the server, or that need special server settings, always start their own
//! server with Docker.
#![cfg(feature = "docker-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use aegis_bus::{BusConfig, NatsAuth, NatsBus, StorageKind, StreamStatus};
use aegis_contracts::bus::BusStream;
use aegis_contracts::{Error, MessageBus};
use async_nats::jetstream;
use async_nats::jetstream::stream::{DiscardPolicy, RetentionPolicy, StorageType};
use futures::TryStreamExt;
use secrecy::SecretString;

use support::jwt::Operator;
use support::nats_server::{NatsServer, ServerOptions, unique_token};
use support::{Case, WAIT, next_item, next_text, take_texts, text};

/// One test on the shared server. Each test has its own stream and its own subjects.
struct Fixture {
    case: Case,
    config: BusConfig,
    /// Keeps the shared container until the test ends.
    _server: Arc<NatsServer>,
}

impl Fixture {
    fn case(&self) -> &Case {
        &self.case
    }

    /// Deletes the stream of the test, so that a shared server does not collect streams.
    async fn finish(self) {
        delete_stream(&self.config).await;
    }
}

/// The configuration for a new stream on `server`. `root` is the first subject token.
/// The storage limit of each test stream.
const TEST_STREAM_MAX_BYTES: u64 = 16 * 1024 * 1024;

fn config_for(server: &NatsServer, root: &str) -> BusConfig {
    let mut config = BusConfig::default();
    config.nats.urls = vec![server.url().to_owned()];
    config.nats.connection_name = "aegis-bus-tests".to_owned();
    config.stream.name = format!("AEGIS_TEST_{root}");
    config.stream.subjects = vec![format!("{root}.>")];
    // The server reserves `max_bytes` of storage for each stream. The default of 1 GiB for
    // each test stream is more than a small test server has.
    config.stream.max_bytes = TEST_STREAM_MAX_BYTES;
    config
}

/// The shared server, and the configuration for a new stream on it.
fn shared_config() -> (Arc<NatsServer>, BusConfig, String) {
    let server = NatsServer::shared();
    let root = unique_token();
    let config = config_for(&server, &root);
    (server, config, root)
}

/// The NATS bus from the public constructor, on the shared server.
async fn nats() -> Fixture {
    let (server, config, root) = shared_config();
    let bus = aegis_bus::connect(&config)
        .await
        .expect("the bus must connect to the test server");
    Fixture {
        case: Case {
            bus,
            root,
            redelivers_unacknowledged: true,
        },
        config,
        _server: server,
    }
}

/// Connects with [`NatsBus::connect`] and makes sure that the stream exists.
async fn nats_bus(config: &BusConfig) -> Arc<NatsBus> {
    let bus = NatsBus::connect(config)
        .await
        .expect("the bus must connect to the test server");
    bus.ensure_stream().await.expect("the stream must be ready");
    Arc::new(bus)
}

fn case_for(bus: Arc<NatsBus>, root: &str) -> Case {
    Case {
        bus,
        root: root.to_owned(),
        redelivers_unacknowledged: true,
    }
}

/// A JetStream context for the administration steps of a test. It does not use the bus.
async fn admin(config: &BusConfig) -> jetstream::Context {
    let client = async_nats::connect(config.nats.urls[0].as_str())
        .await
        .expect("an administration connection");
    jetstream::new(client)
}

async fn admin_stream(config: &BusConfig) -> jetstream::stream::Stream {
    admin(config)
        .await
        .get_stream(&config.stream.name)
        .await
        .expect("the stream must exist")
}

async fn stream_settings(config: &BusConfig) -> jetstream::stream::Config {
    admin_stream(config).await.cached_info().config.clone()
}

async fn consumer_names(config: &BusConfig) -> Vec<String> {
    let mut names: Vec<String> = admin_stream(config)
        .await
        .consumer_names()
        .try_collect()
        .await
        .expect("the consumer names");
    names.sort();
    names
}

/// Returns the name of the consumer of the only ephemeral subscription of the stream.
async fn only_ephemeral_consumer(config: &BusConfig) -> String {
    let names = consumer_names(config).await;
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(names[0].starts_with("aegis-ephemeral-"), "{names:?}");
    names[0].clone()
}

async fn delete_consumer(config: &BusConfig, name: &str) {
    admin_stream(config)
        .await
        .delete_consumer(name)
        .await
        .expect("the consumer must be deletable");
}

async fn delete_stream(config: &BusConfig) {
    admin(config)
        .await
        .delete_stream(&config.stream.name)
        .await
        .expect("the stream of the test must be deletable");
}

/// Asks again until `check` returns a value. Fails after [`WAIT`].
async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Reads messages until the payload `last` arrives. Each error item must be retryable.
/// Returns the payloads and the errors.
async fn texts_until(stream: &mut BusStream, last: &str) -> (Vec<String>, Vec<Error>) {
    let mut texts = Vec::new();
    let mut errors = Vec::new();
    loop {
        match next_item(stream).await {
            Some(Ok(message)) => {
                texts.push(text(&message));
                if texts.last().map(String::as_str) == Some(last) {
                    return (texts, errors);
                }
            }
            Some(Err(error)) => {
                assert!(
                    error.is_retryable(),
                    "a stream that continues must give retryable errors only, got {error:?}"
                );
                errors.push(error);
            }
            None => panic!("the stream ended before {last:?}; got {texts:?} and {errors:?}"),
        }
    }
}

/// Publishes, and tries again after a retryable error. A retry can store a duplicate.
async fn publish_with_retry(case: &Case, rest: &str, payload: &str) {
    let subject = case.subject(rest);
    eventually(
        "the publish must succeed after the server is back",
        || async {
            match case
                .bus
                .publish(&subject, payload.as_bytes().to_vec())
                .await
            {
                Ok(()) => Some(()),
                Err(error) if error.is_retryable() => None,
                Err(error) => {
                    panic!("the publish failed with an error that is not retryable: {error:?}")
                }
            }
        },
    )
    .await;
}

fn unauthorized(result: Result<impl Sized, Error>) -> String {
    match result {
        Err(Error::Unauthorized(message)) => message,
        Err(other) => panic!("expected Unauthorized, got {other:?}"),
        Ok(_) => panic!("expected Unauthorized, got a success"),
    }
}

fn unavailable(result: Result<impl Sized, Error>) -> String {
    match result {
        Err(Error::Unavailable(message)) => message,
        Err(other) => panic!("expected Unavailable, got {other:?}"),
        Ok(_) => panic!("expected Unavailable, got a success"),
    }
}

fn config_error(result: Result<impl Sized, Error>) -> String {
    match result {
        Err(Error::Config(message)) => message,
        Err(other) => panic!("expected Config, got {other:?}"),
        Ok(_) => panic!("expected Config, got a success"),
    }
}

fn user_password(user: &str, password: &str) -> NatsAuth {
    NatsAuth::UserPassword {
        user: user.to_owned(),
        password: SecretString::from(password),
    }
}

mod nats_bus {
    use super::nats;
    use crate::support;

    support::core_semantic_tests!(nats);
    support::strict_semantic_tests!(nats);
}

#[tokio::test]
async fn ensure_stream_creates_the_stream_with_the_configured_settings() {
    let (_server, mut config, _) = shared_config();
    config.stream.max_age = Duration::from_secs(3600);
    config.stream.max_bytes = 64 * 1024 * 1024;
    config.stream.storage = StorageKind::Memory;
    let bus = NatsBus::connect(&config).await.unwrap();

    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Created);
    let settings = stream_settings(&config).await;
    assert_eq!(settings.name, config.stream.name);
    assert_eq!(settings.subjects, config.stream.subjects);
    assert_eq!(settings.max_age, Duration::from_secs(3600));
    assert_eq!(settings.max_bytes, 64 * 1024 * 1024);
    assert_eq!(settings.storage, StorageType::Memory);
    assert_eq!(settings.num_replicas, 1);
    assert_eq!(settings.retention, RetentionPolicy::Limits);
    assert_eq!(settings.discard, DiscardPolicy::Old);

    // A second call, and a call from a second connection, change nothing.
    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Unchanged);
    let second = NatsBus::connect(&config).await.unwrap();
    assert_eq!(
        second.ensure_stream().await.unwrap(),
        StreamStatus::Unchanged
    );
    assert_eq!(stream_settings(&config).await, settings);
    delete_stream(&config).await;
}

#[tokio::test]
async fn ensure_stream_makes_a_stream_with_the_default_file_storage_and_no_limits() {
    let (_server, mut config, _) = shared_config();
    config.stream.max_age = Duration::ZERO;
    config.stream.max_bytes = 0;
    let bus = NatsBus::connect(&config).await.unwrap();
    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Created);
    let settings = stream_settings(&config).await;
    assert_eq!(settings.storage, StorageType::File);
    assert_eq!(settings.max_age, Duration::ZERO);
    assert_eq!(settings.max_bytes, -1);
    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Unchanged);
    delete_stream(&config).await;
}

#[tokio::test]
async fn ensure_stream_updates_a_stream_that_has_different_settings() {
    let (_server, config, root) = shared_config();
    let first = nats_bus(&config).await;
    let subject = format!("{root}.events.file");
    first.publish(&subject, b"kept".to_vec()).await.unwrap();

    let second_root = unique_token();
    let mut changed = config.clone();
    changed.stream.subjects.push(format!("{second_root}.>"));
    changed.stream.max_age = Duration::from_secs(2 * 3600);
    changed.stream.max_bytes = 0;
    let second = NatsBus::connect(&changed).await.unwrap();
    assert_eq!(second.ensure_stream().await.unwrap(), StreamStatus::Updated);
    assert_eq!(
        second.ensure_stream().await.unwrap(),
        StreamStatus::Unchanged
    );

    let settings = stream_settings(&changed).await;
    assert_eq!(settings.subjects, changed.stream.subjects);
    assert_eq!(settings.max_age, Duration::from_secs(2 * 3600));
    assert_eq!(settings.max_bytes, -1);
    assert_eq!(settings.storage, StorageType::File);

    // The update keeps the stored messages, and the stream stores the new subjects.
    second
        .publish(&format!("{second_root}.audit"), b"new subject".to_vec())
        .await
        .unwrap();
    let mut stream = second.subscribe(">", Some("reader")).await.unwrap();
    assert_eq!(take_texts(&mut stream, 2).await, ["kept", "new subject"]);

    // The first connection has the old settings. It changes the stream back.
    assert_eq!(first.ensure_stream().await.unwrap(), StreamStatus::Updated);
    assert_eq!(
        stream_settings(&config).await.subjects,
        config.stream.subjects
    );
    delete_stream(&config).await;
}

#[tokio::test]
async fn ensure_stream_from_two_connections_at_the_same_time_succeeds() {
    let (_server, config, _) = shared_config();
    let left = NatsBus::connect(&config).await.unwrap();
    let right = NatsBus::connect(&config).await.unwrap();
    let (left_status, right_status) = tokio::join!(left.ensure_stream(), right.ensure_stream());
    let statuses = [left_status.unwrap(), right_status.unwrap()];
    assert!(
        statuses.contains(&StreamStatus::Created),
        "one call or more must create the stream: {statuses:?}"
    );
    assert!(
        !statuses.contains(&StreamStatus::Updated),
        "the two calls have the same settings: {statuses:?}"
    );
    assert_eq!(left.ensure_stream().await.unwrap(), StreamStatus::Unchanged);
    delete_stream(&config).await;
}

#[tokio::test]
async fn ensure_stream_does_not_change_the_storage_of_a_stream() {
    let (_server, mut config, _) = shared_config();
    config.stream.storage = StorageKind::Memory;
    nats_bus(&config).await;

    let mut changed = config.clone();
    changed.stream.storage = StorageKind::File;
    let bus = NatsBus::connect(&changed).await.unwrap();
    let message = config_error(bus.ensure_stream().await);
    assert_eq!(
        message,
        format!(
            "the stream {:?} has the storage Memory, but stream.storage is File; JetStream \
             cannot change the storage of a stream",
            config.stream.name
        )
    );
    assert_eq!(stream_settings(&config).await.storage, StorageType::Memory);
    delete_stream(&config).await;
}

#[tokio::test]
async fn a_stream_that_the_bus_does_not_manage_is_only_checked() {
    let (_server, config, root) = shared_config();
    let mut unmanaged = config.clone();
    unmanaged.stream.manage = false;
    unmanaged.stream.max_age = Duration::from_secs(60);

    let bus = NatsBus::connect(&unmanaged).await.unwrap();
    let message = config_error(bus.ensure_stream().await);
    assert_eq!(
        message,
        format!(
            "the stream {:?} does not exist and stream.manage is false; create the stream on \
             the NATS server",
            config.stream.name
        )
    );

    // An administrator creates the stream. The bus then accepts it and does not change it.
    nats_bus(&config).await;
    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Unchanged);
    assert_eq!(
        stream_settings(&config).await.max_age,
        config.stream.max_age
    );

    let mut other_subjects = unmanaged.clone();
    other_subjects.stream.subjects = vec![format!("{root}.events.>")];
    let bus = NatsBus::connect(&other_subjects).await.unwrap();
    let message = config_error(bus.ensure_stream().await);
    assert_eq!(
        message,
        format!(
            "the stream {:?} stores the subjects [{root}.>], but stream.subjects is \
             [{root}.events.>]",
            config.stream.name
        )
    );
    delete_stream(&config).await;
}

#[tokio::test]
async fn publish_and_subscribe_need_the_stream() {
    let (_server, config, root) = shared_config();
    let bus = NatsBus::connect(&config).await.unwrap();
    let subject = format!("{root}.events.file");

    let message = unavailable(bus.publish(&subject, b"x".to_vec()).await);
    assert_eq!(
        message,
        format!(
            "publish to {subject:?}: no JetStream stream stores this subject; make sure that \
             the stream {:?} exists",
            config.stream.name
        )
    );
    let pattern = format!("{root}.>");
    let message = unavailable(bus.subscribe(&pattern, Some("detect")).await.map(|_| ()));
    assert_eq!(
        message,
        "open the durable consumer \"detect\": the stream does not exist on the NATS server"
    );
    let message = unavailable(bus.subscribe(&pattern, None).await.map(|_| ()));
    assert_eq!(
        message,
        "open an ephemeral consumer: stream not found (code 404, error code 10059)"
    );

    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Created);
    bus.publish(&subject, b"stored".to_vec()).await.unwrap();
    let mut stream = bus.subscribe(&pattern, Some("detect")).await.unwrap();
    assert_eq!(next_text(&mut stream).await, "stored");
    delete_stream(&config).await;
}

#[tokio::test]
async fn a_message_that_is_too_large_for_the_server_is_not_valid() {
    let (_server, config, root) = shared_config();
    let bus = nats_bus(&config).await;
    let limit = admin(&config).await.client().server_info().max_payload;
    let result = bus
        .publish(&format!("{root}.events.file"), vec![0; limit + 1])
        .await;
    match result {
        Err(Error::InvalidInput(message)) => assert!(
            message.starts_with("the message is too large for the NATS server"),
            "{message}"
        ),
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    // The bus stored nothing.
    let state = admin_stream(&config).await.cached_info().state.clone();
    assert_eq!(state.messages, 0);
    delete_stream(&config).await;
}

#[tokio::test]
async fn a_durable_consumer_continues_on_a_new_connection() {
    let (_server, mut config, root) = shared_config();
    // If the first connection closes before it gives message 3 back, the server sends
    // the message again after this time.
    config.consumer.ack_wait = Duration::from_secs(2);
    {
        let case = case_for(nats_bus(&config).await, &root);
        for payload in ["1", "2", "3", "4", "5"] {
            case.publish("events.file", payload).await;
        }
        let mut stream = case.subscribe("events.>", Some("detect")).await;
        // The polls for messages 2 and 3 acknowledge messages 1 and 2.
        assert_eq!(take_texts(&mut stream, 3).await, ["1", "2", "3"]);
    }

    let case = case_for(nats_bus(&config).await, &root);
    let mut resumed = case.subscribe("events.>", Some("detect")).await;
    // No message is lost. Message 3 had no acknowledgement, so it arrives again.
    let mut received = take_texts(&mut resumed, 3).await;
    received.sort();
    assert_eq!(received, ["3", "4", "5"]);
    // The end marker comes directly after them. Thus, messages 1 and 2 did not come again.
    case.publish("events.file", "end").await;
    assert_eq!(next_text(&mut resumed).await, "end");
    delete_stream(&config).await;
}

#[tokio::test]
async fn the_server_sends_a_message_again_when_no_acknowledgement_arrives() {
    let (_server, mut config, root) = shared_config();
    config.consumer.ack_wait = Duration::from_secs(2);
    let case = case_for(nats_bus(&config).await, &root);
    case.publish("events.file", "1").await;

    // The holder gets the message and then does no more work. It stays connected.
    let mut holder = case.subscribe("events.>", Some("workers")).await;
    assert_eq!(next_text(&mut holder).await, "1");

    let mut waiter = case.subscribe("events.>", Some("workers")).await;
    assert_eq!(next_text(&mut waiter).await, "1");
    // The next poll of the waiter acknowledges the message. It does not come a third time.
    case.publish("events.file", "2").await;
    assert_eq!(next_text(&mut waiter).await, "2");
    case.publish("events.file", "3").await;
    assert_eq!(next_text(&mut waiter).await, "3");
    drop(holder);
    delete_stream(&config).await;
}

#[tokio::test]
async fn a_late_consumer_does_not_give_back_a_message_that_the_server_sent_again() {
    let (_server, mut config, root) = shared_config();
    // The second consumer must still hold message 1 when the third consumer gets its
    // message. A long `ack_wait` keeps that true on a slow test computer.
    config.consumer.ack_wait = Duration::from_secs(8);
    let case = case_for(nats_bus(&config).await, &root);
    case.publish("events.file", "1").await;

    let mut holder = case.subscribe("events.>", Some("workers")).await;
    assert_eq!(next_text(&mut holder).await, "1");
    // After `ack_wait`, the server sends message 1 to the second consumer.
    let mut second = case.subscribe("events.>", Some("workers")).await;
    assert_eq!(next_text(&mut second).await, "1");

    // The second consumer still works on message 1 when the holder goes away. If the
    // holder gave the message back now, the server would send it a third time, to the
    // consumer that waits.
    let mut third = case.subscribe("events.>", Some("workers")).await;
    let waiting = async { next_text(&mut third).await };
    let release = async {
        tokio::task::yield_now().await;
        drop(holder);
        case.publish("events.file", "2").await;
    };
    let (received, ()) = tokio::join!(waiting, release);
    assert_eq!(received, "2");
    drop(second);
    delete_stream(&config).await;
}

#[tokio::test]
async fn a_changed_ack_wait_updates_the_durable_consumer() {
    let (_server, config, root) = shared_config();
    let pattern = format!("{root}.>");
    let first = nats_bus(&config).await;
    let _stream = first.subscribe(&pattern, Some("detect")).await.unwrap();
    let ack_wait = |config: BusConfig| async move {
        let stream = admin_stream(&config).await;
        let info = stream.consumer_info("detect").await.unwrap();
        (info.config.ack_wait, info.config.filter_subject)
    };
    assert_eq!(
        ack_wait(config.clone()).await,
        (Duration::from_secs(30), pattern.clone())
    );

    let mut changed = config.clone();
    changed.consumer.ack_wait = Duration::from_secs(90);
    let second = nats_bus(&changed).await;
    let mut stream = second.subscribe(&pattern, Some("detect")).await.unwrap();
    assert_eq!(
        ack_wait(config.clone()).await,
        (Duration::from_secs(90), pattern.clone())
    );
    // The consumer is the same consumer: it has the position of the durable name.
    second
        .publish(&format!("{root}.audit"), b"record".to_vec())
        .await
        .unwrap();
    assert_eq!(next_text(&mut stream).await, "record");
    assert_eq!(consumer_names(&config).await, ["detect"]);
    delete_stream(&config).await;
}

#[tokio::test]
async fn a_durable_subscription_ends_when_its_consumer_is_deleted() {
    let (_server, config, root) = shared_config();
    let case = case_for(nats_bus(&config).await, &root);
    let mut stream = case.subscribe("events.>", Some("detect")).await;
    case.publish("events.file", "1").await;
    assert_eq!(next_text(&mut stream).await, "1");

    delete_consumer(&config, "detect").await;
    let message = unavailable(next_item(&mut stream).await.expect("one last error"));
    assert_eq!(
        message,
        "the NATS server no longer has the durable consumer \"detect\"; the subscription \
         ends; subscribe again"
    );
    assert!(next_item(&mut stream).await.is_none());

    // A new subscription makes the consumer again. A new consumer starts at the first message.
    let mut again = case.subscribe("events.>", Some("detect")).await;
    assert_eq!(next_text(&mut again).await, "1");
    delete_stream(&config).await;
}

#[tokio::test]
async fn an_ephemeral_subscription_replaces_a_consumer_that_the_server_lost() {
    const LOST: &str = "an ephemeral subscription lost its consumer; a new consumer continues \
                        at the same position";
    let (_server, config, root) = shared_config();
    let case = case_for(nats_bus(&config).await, &root);

    // The server loses the consumer before the subscription got a message. The new
    // consumer must start after the message that was in the stream at the subscribe time.
    case.publish("events.file", "old").await;
    let mut stream = case.subscribe("events.>", None).await;
    let first = only_ephemeral_consumer(&config).await;
    delete_consumer(&config, &first).await;
    case.publish("events.file", "1").await;
    case.publish("events.file", "2").await;
    let (texts, errors) = texts_until(&mut stream, "2").await;
    assert_eq!(texts, ["1", "2"]);
    assert_eq!(errors.len(), 1, "{errors:?}");
    let message = unavailable(Err::<(), _>(errors.into_iter().next().unwrap()));
    assert!(message.starts_with(LOST), "{message}");

    // The server loses the consumer again, after the subscription got messages.
    let second = only_ephemeral_consumer(&config).await;
    assert_ne!(second, first);
    delete_consumer(&config, &second).await;
    case.publish("events.file", "3").await;
    case.publish("events.file", "4").await;
    let (texts, errors) = texts_until(&mut stream, "4").await;
    assert_eq!(texts, ["3", "4"]);
    assert_eq!(errors.len(), 1, "{errors:?}");
    let message = unavailable(Err::<(), _>(errors.into_iter().next().unwrap()));
    assert!(message.starts_with(LOST), "{message}");
    assert_ne!(only_ephemeral_consumer(&config).await, second);
    delete_stream(&config).await;
}

#[tokio::test]
async fn an_ephemeral_subscription_deletes_its_consumer_when_it_ends() {
    let (_server, config, root) = shared_config();
    let case = case_for(nats_bus(&config).await, &root);
    let durable = case.subscribe("events.>", Some("detect")).await;
    let ephemeral = case.subscribe("events.>", None).await;
    assert_eq!(consumer_names(&config).await.len(), 2);

    drop(ephemeral);
    drop(durable);
    // The durable consumer stays. It keeps the position of the durable name.
    eventually("the server deletes the ephemeral consumer", || async {
        (consumer_names(&config).await == ["detect"]).then_some(())
    })
    .await;
    delete_stream(&config).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriptions_continue_after_a_restart_of_the_server() {
    let server = Arc::new(NatsServer::start(&ServerOptions::default()));
    let root = unique_token();
    let mut config = config_for(&server, &root);
    // The restart deletes the consumer of the ephemeral subscription. The subscription
    // finds this after two missed heartbeats: `pull_expires`.
    config.consumer.pull_expires = Duration::from_secs(2);
    let case = case_for(nats_bus(&config).await, &root);

    let mut durable = case.subscribe(">", Some("detect")).await;
    let mut ephemeral = case.subscribe(">", None).await;
    case.publish("events.file", "1").await;
    case.publish("events.file", "2").await;
    // The durable consumer acknowledged message 1. Message 2 has no acknowledgement.
    assert_eq!(take_texts(&mut durable, 2).await, ["1", "2"]);
    assert_eq!(take_texts(&mut ephemeral, 2).await, ["1", "2"]);
    // The stream stores message 3 before the restart. No subscriber read it.
    case.publish("events.file", "3").await;

    let restarted = server.clone();
    tokio::task::spawn_blocking(move || restarted.restart())
        .await
        .expect("the restart must not panic");
    publish_with_retry(&case, "events.file", "4").await;

    // The same streams continue. The durable consumer loses no message. Message 2 can
    // arrive again, because the restart can lose its acknowledgement.
    let (texts, _) = texts_until(&mut durable, "4").await;
    let after_two: Vec<&str> = texts
        .iter()
        .map(String::as_str)
        .filter(|text| *text != "2")
        .collect();
    assert_eq!(after_two, ["3", "4"], "all messages: {texts:?}");
    // The ephemeral subscription gets each message one time, in sequence.
    let (texts, _) = texts_until(&mut ephemeral, "4").await;
    assert_eq!(texts, ["3", "4"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriptions_report_an_outage_and_then_continue() {
    let server = Arc::new(NatsServer::start(&ServerOptions::default()));
    let root = unique_token();
    let mut config = config_for(&server, &root);
    // The subscriptions find the outage after two missed heartbeats: `pull_expires`.
    config.consumer.pull_expires = Duration::from_secs(2);
    config.nats.request_timeout = Duration::from_secs(1);
    let case = case_for(nats_bus(&config).await, &root);
    let mut durable = case.subscribe(">", Some("detect")).await;
    let mut ephemeral = case.subscribe(">", None).await;
    case.publish("audit", "1").await;
    assert_eq!(next_text(&mut durable).await, "1");
    assert_eq!(next_text(&mut ephemeral).await, "1");

    // The server stops to answer. The connection stays open.
    let paused = server.clone();
    tokio::task::spawn_blocking(move || paused.pause())
        .await
        .expect("the pause must not panic");

    let subject = case.subject("audit");
    let result = case
        .bus
        .publish(&subject, b"during the outage".to_vec())
        .await;
    match result {
        Err(Error::Timeout(message)) => assert_eq!(
            message,
            format!("publish to {subject:?}: the NATS server did not answer in time")
        ),
        other => panic!("expected Timeout, got {other:?}"),
    }
    let message = unavailable(next_item(&mut durable).await.expect("the stream continues"));
    assert_eq!(
        message,
        "no heartbeat from the NATS server for the durable consumer \"detect\"; the \
         subscription continues when the connection is back"
    );
    let message = unavailable(
        next_item(&mut ephemeral)
            .await
            .expect("the stream continues"),
    );
    assert_eq!(
        message,
        "an ephemeral subscription lost its consumer; a new consumer continues at the same \
         position: missed idle heartbeat"
    );

    let resumed = server.clone();
    tokio::task::spawn_blocking(move || resumed.resume())
        .await
        .expect("the resume must not panic");
    publish_with_retry(&case, "audit", "2").await;

    // The server got the first publish request before it stopped to answer, and it stores
    // the message after the outage. Thus, a publish that returns a retryable error can
    // have a stored message. The same streams continue, and no message is lost.
    let (texts, _) = texts_until(&mut durable, "2").await;
    assert_eq!(texts, ["during the outage", "2"]);
    let (texts, _) = texts_until(&mut ephemeral, "2").await;
    assert_eq!(texts, ["during the outage", "2"]);
}

const AUTH_SERVER_CONFIG: &str = r#"
authorization {
  users = [
    { user: "aegis", password: "correct-horse-battery" }
    {
      user: "limited"
      password: "limited-staple-password"
      permissions: {
        publish: { allow: ["_INBOX.>"] }
        subscribe: { allow: ["_INBOX.>"] }
      }
    }
  ]
}
"#;

#[tokio::test]
async fn a_server_with_users_rejects_missing_and_wrong_credentials() {
    let server = NatsServer::start(&ServerOptions {
        config: Some(AUTH_SERVER_CONFIG.to_owned()),
        ..ServerOptions::default()
    });
    let root = unique_token();
    let mut config = config_for(&server, &root);

    let message = unauthorized(NatsBus::connect(&config).await);
    assert_eq!(
        message,
        "connect to NATS: authorization violation: nats: authorization violation"
    );

    config.nats.auth = user_password("aegis", "wrong-horse-battery");
    let message = unauthorized(aegis_bus::connect(&config).await.map(|_| ()));
    assert_eq!(
        message,
        "connect to NATS: authorization violation: nats: authorization violation"
    );

    config.nats.auth = user_password("aegis", "correct-horse-battery");
    let bus = aegis_bus::connect(&config)
        .await
        .expect("the correct password must connect");
    let subject = format!("{root}.audit");
    bus.publish(&subject, b"record".to_vec()).await.unwrap();
    let mut stream = bus.subscribe(&subject, Some("archive")).await.unwrap();
    assert_eq!(next_text(&mut stream).await, "record");
}

#[tokio::test]
async fn an_account_with_no_permission_gets_unauthorized() {
    let server = NatsServer::start(&ServerOptions {
        config: Some(AUTH_SERVER_CONFIG.to_owned()),
        ..ServerOptions::default()
    });
    let root = unique_token();
    let mut config = config_for(&server, &root);
    config.nats.auth = user_password("aegis", "correct-horse-battery");
    nats_bus(&config).await;

    // The server gives no answer to a request that it does not permit. The bus waits
    // for the request time limit, and then reports the permission error.
    config.nats.auth = user_password("limited", "limited-staple-password");
    config.nats.request_timeout = Duration::from_secs(1);
    let bus = NatsBus::connect(&config)
        .await
        .expect("the limited user can connect");
    let stream = &config.stream.name;
    let denied = "the NATS server denied permission to this account";

    let message = unauthorized(bus.ensure_stream().await);
    assert_eq!(message, format!("read the stream {stream:?}: {denied}"));
    let subject = format!("{root}.audit");
    let message = unauthorized(bus.publish(&subject, b"record".to_vec()).await);
    assert_eq!(message, format!("publish to {subject:?}: {denied}"));
    let message = unauthorized(bus.subscribe(&subject, Some("archive")).await.map(|_| ()));
    assert_eq!(
        message,
        format!("open the durable consumer \"archive\": {denied}")
    );
    let message = unauthorized(bus.subscribe(&subject, None).await.map(|_| ()));
    assert_eq!(message, format!("open an ephemeral consumer: {denied}"));

    // The server stored nothing from the limited user.
    config.nats.auth = user_password("aegis", "correct-horse-battery");
    let full = nats_bus(&config).await;
    full.publish(&subject, b"permitted".to_vec()).await.unwrap();
    let mut stream = full.subscribe(&subject, Some("reader")).await.unwrap();
    assert_eq!(next_text(&mut stream).await, "permitted");
}

#[tokio::test]
async fn an_account_with_the_documented_permissions_can_use_the_bus() {
    // The README has this list of permissions.
    let root = unique_token();
    let stream = format!("AEGIS_TEST_{root}");
    let server_config = format!(
        r#"
authorization {{
  users = [
    {{
      user: "aegis"
      password: "least-privilege-password"
      permissions: {{
        publish: {{
          allow: [
            "{root}.>"
            "$JS.API.STREAM.INFO.{stream}"
            "$JS.API.STREAM.CREATE.{stream}"
            "$JS.API.STREAM.UPDATE.{stream}"
            "$JS.API.CONSUMER.INFO.{stream}.*"
            "$JS.API.CONSUMER.CREATE.{stream}.>"
            "$JS.API.CONSUMER.DELETE.{stream}.*"
            "$JS.API.CONSUMER.MSG.NEXT.{stream}.*"
            "$JS.ACK.{stream}.>"
          ]
        }}
        subscribe: {{ allow: ["_INBOX.>"] }}
      }}
    }}
    {{ user: "administrator", password: "administrator-password" }}
  ]
}}
"#
    );
    let server = NatsServer::start(&ServerOptions {
        config: Some(server_config),
        ..ServerOptions::default()
    });
    let mut config = config_for(&server, &root);
    assert_eq!(config.stream.name, stream);
    config.nats.auth = user_password("aegis", "least-privilege-password");
    // A request that the server does not permit must fail fast in this test.
    config.nats.request_timeout = Duration::from_secs(2);

    let bus = NatsBus::connect(&config).await.unwrap();
    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Created);
    let mut changed = config.clone();
    changed.stream.max_age = Duration::from_secs(3600);
    let bus = NatsBus::connect(&changed).await.unwrap();
    assert_eq!(bus.ensure_stream().await.unwrap(), StreamStatus::Updated);

    let case = case_for(Arc::new(bus), &root);
    let mut ephemeral = case.subscribe("events.>", None).await;
    for payload in ["1", "2", "3"] {
        case.publish("events.file", payload).await;
    }
    assert_eq!(take_texts(&mut ephemeral, 3).await, ["1", "2", "3"]);
    let mut durable = case.subscribe("events.>", Some("detect")).await;
    assert_eq!(take_texts(&mut durable, 2).await, ["1", "2"]);
    // The drop gives message 2 back, and it deletes the ephemeral consumer.
    drop(durable);
    drop(ephemeral);
    let mut resumed = case.subscribe("events.>", Some("detect")).await;
    let mut received = take_texts(&mut resumed, 2).await;
    received.sort();
    assert_eq!(received, ["2", "3"]);

    let administrator = async_nats::ConnectOptions::with_user_and_password(
        "administrator".to_owned(),
        "administrator-password".to_owned(),
    )
    .connect(server.url())
    .await
    .expect("an administration connection");
    let stream = jetstream::new(administrator)
        .get_stream(&stream)
        .await
        .expect("the stream must exist");
    eventually("the server deletes the ephemeral consumer", || async {
        let names: Vec<String> = stream.consumer_names().try_collect().await.unwrap();
        (names == ["detect"]).then_some(())
    })
    .await;
}

#[tokio::test]
async fn a_server_with_a_token_rejects_a_wrong_token() {
    let server = NatsServer::start(&ServerOptions {
        config: Some("authorization { token: \"s3cr3t-bus-token\" }".to_owned()),
        ..ServerOptions::default()
    });
    let root = unique_token();
    let mut config = config_for(&server, &root);

    config.nats.auth = NatsAuth::Token {
        token: SecretString::from("wrong-bus-token"),
    };
    let message = unauthorized(NatsBus::connect(&config).await);
    assert_eq!(
        message,
        "connect to NATS: authorization violation: nats: authorization violation"
    );

    config.nats.auth = NatsAuth::Token {
        token: SecretString::from("s3cr3t-bus-token"),
    };
    let case = case_for(nats_bus(&config).await, &root);
    let mut stream = case.subscribe("audit", None).await;
    case.publish("audit", "record").await;
    assert_eq!(next_text(&mut stream).await, "record");
}

#[tokio::test]
async fn a_server_with_no_jetstream_is_unavailable() {
    let server = NatsServer::start(&ServerOptions {
        jetstream: false,
        ..ServerOptions::default()
    });
    let root = unique_token();
    let config = config_for(&server, &root);
    let bus = NatsBus::connect(&config)
        .await
        .expect("the connection needs no JetStream");
    let expected = format!(
        "read the stream {:?}: JetStream did not answer; it is not enabled or not ready",
        config.stream.name
    );
    assert_eq!(unavailable(bus.ensure_stream().await), expected);
    assert_eq!(
        unavailable(aegis_bus::connect(&config).await.map(|_| ())),
        expected
    );
    let subject = format!("{root}.audit");
    let message = unavailable(bus.publish(&subject, b"record".to_vec()).await);
    assert!(
        message.contains("no JetStream stream stores this subject"),
        "{message}"
    );
}

#[tokio::test]
async fn a_credentials_file_signs_in_a_user_of_the_account() {
    let operator = Operator::new();
    let server = NatsServer::start(&ServerOptions {
        config: Some(operator.server_config()),
        ..ServerOptions::default()
    });
    let root = unique_token();
    let mut config = config_for(&server, &root);
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("aegis.creds");
    const REJECTED: &str =
        "connect to NATS: authorization violation: nats: authorization violation";

    assert_eq!(unauthorized(NatsBus::connect(&config).await), REJECTED);

    // A user of a different operator. The server does not know its account.
    config.nats.auth = NatsAuth::CredentialsFile { path: path.clone() };
    std::fs::write(&path, Operator::new().user_credentials("aegis")).expect("write the file");
    assert_eq!(unauthorized(NatsBus::connect(&config).await), REJECTED);

    std::fs::write(&path, operator.user_credentials("aegis")).expect("write the file");
    let case = case_for(nats_bus(&config).await, &root);
    case.publish("audit", "record").await;
    let mut stream = case.subscribe("audit", Some("archive")).await;
    assert_eq!(next_text(&mut stream).await, "record");
}
