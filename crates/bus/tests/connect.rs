//! The connection errors that need no NATS server.
//!
//! The tests use only sockets and files of the local host.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::time::Duration;

use aegis_bus::{BusConfig, BusKind, NatsAuth, NatsBus};
use aegis_contracts::Error;

/// The longest time that a connection attempt of a test can take.
const WAIT: Duration = Duration::from_secs(20);

/// A configuration for a NATS server on a port of the local host.
fn config_for_port(port: u16) -> BusConfig {
    let mut config = BusConfig::default();
    config.nats.urls = vec![format!("nats://127.0.0.1:{port}")];
    config
}

/// A port of the local host that has no listener.
fn closed_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port");
    listener.local_addr().expect("the address").port()
}

async fn connect_error(config: &BusConfig) -> Error {
    tokio::time::timeout(WAIT, NatsBus::connect(config))
        .await
        .expect("the connection attempt must end in time")
        .expect_err("the connection must fail")
}

fn config_message(error: Error) -> String {
    match error {
        Error::Config(message) => message,
        other => panic!("expected Config, got {other:?}"),
    }
}

#[tokio::test]
async fn a_server_that_refuses_the_connection_is_unavailable() {
    let config = config_for_port(closed_port());
    let error = connect_error(&config).await;
    assert!(
        matches!(&error, Error::Unavailable(message) if message.starts_with("connect to NATS: IO error")),
        "{error:?}"
    );
    assert!(error.is_retryable());

    // The public constructor gives the same error.
    let error = aegis_bus::connect(&config)
        .await
        .err()
        .expect("the connection must fail");
    assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
}

#[tokio::test]
async fn a_server_that_does_not_answer_is_a_timeout() {
    // The listener completes the TCP handshake, but it never sends the NATS greeting.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a listener");
    let mut config = config_for_port(listener.local_addr().expect("the address").port());
    config.nats.connect_timeout = Duration::from_millis(200);

    let error = connect_error(&config).await;
    assert!(
        matches!(&error, Error::Timeout(message) if message == "connect to NATS: timed out"),
        "{error:?}"
    );
    assert!(error.is_retryable());
    drop(listener);
}

#[tokio::test]
async fn a_configuration_that_is_not_valid_fails_before_the_connection() {
    // A listener that got a connection would make the test hang, so it proves that the bus
    // made no connection.
    let mut config = config_for_port(closed_port());
    config.stream.replicas = 0;
    let error = connect_error(&config).await;
    assert_eq!(config_message(error), "stream.replicas must be from 1 to 5");

    config.stream.replicas = 1;
    config.consumer.pull_batch = 0;
    let error = aegis_bus::connect(&config)
        .await
        .err()
        .expect("the configuration is not valid");
    assert_eq!(
        config_message(error),
        "consumer.pull_batch must be from 1 to 10000"
    );
}

#[tokio::test]
async fn a_tls_file_that_is_not_readable_is_a_configuration_error() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let present = directory.path().join("present.pem");
    std::fs::write(&present, "not a certificate").expect("write a file");
    let missing = directory.path().join("missing.pem");
    let reason = std::fs::File::open(&missing)
        .expect_err("the file must not exist")
        .to_string();
    let expected = |setting: &str| {
        format!(
            "{setting}: cannot read the file {}: {reason}",
            missing.display()
        )
    };

    let mut config = config_for_port(closed_port());
    config.nats.tls.ca_file = Some(missing.clone());
    let error = connect_error(&config).await;
    assert_eq!(config_message(error), expected("nats.tls.ca_file"));

    config.nats.tls.ca_file = Some(present.clone());
    config.nats.tls.client_cert_file = Some(missing.clone());
    config.nats.tls.client_key_file = Some(present.clone());
    let error = connect_error(&config).await;
    assert_eq!(config_message(error), expected("nats.tls.client_cert_file"));

    config.nats.tls.client_cert_file = Some(present.clone());
    config.nats.tls.client_key_file = Some(missing.clone());
    let error = connect_error(&config).await;
    assert_eq!(config_message(error), expected("nats.tls.client_key_file"));
}

#[tokio::test]
async fn a_credentials_file_that_is_not_usable_is_a_configuration_error() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let missing = directory.path().join("missing.creds");
    let reason = std::fs::File::open(&missing)
        .expect_err("the file must not exist")
        .to_string();
    let mut config = config_for_port(closed_port());
    config.nats.auth = NatsAuth::CredentialsFile {
        path: missing.clone(),
    };
    let error = connect_error(&config).await;
    assert_eq!(
        config_message(error),
        format!(
            "nats.auth.path: cannot read the file {}: {reason}",
            missing.display()
        )
    );

    // A file with other content. The error must not show the content.
    let wrong = directory.path().join("wrong.creds");
    std::fs::write(&wrong, "password = do-not-show-this-text\n").expect("write a file");
    config.nats.auth = NatsAuth::CredentialsFile { path: wrong };
    let error = connect_error(&config).await;
    assert_eq!(
        config_message(error),
        "nats.auth.path: the file has no valid user JWT and NKey seed"
    );
}

#[tokio::test]
async fn the_memory_kind_makes_no_connection() {
    // The `nats` and `consumer` sections are not valid, and no server listens.
    let mut config = config_for_port(closed_port());
    config.kind = BusKind::Memory;
    config.nats.urls = Vec::new();
    config.nats.tls.client_cert_file = Some(PathBuf::from("/does/not/exist.pem"));
    config.consumer.pull_batch = 0;
    let bus = aegis_bus::connect(&config)
        .await
        .expect("the in-process bus does not use these settings");
    bus.publish("aegis.audit", b"record".to_vec())
        .await
        .expect("the in-process bus stores the message");

    // The `stream` section applies to the in-process bus.
    config.stream.subjects = Vec::new();
    let error = aegis_bus::connect(&config)
        .await
        .err()
        .expect("the stream section is not valid");
    assert_eq!(
        config_message(error),
        "stream.subjects must have one subject or more"
    );
}
