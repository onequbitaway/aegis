//! The TLS tests of the NATS bus against a real NATS server.
//!
//! The `docker-tests` feature enables these tests. Each test starts its own server with
//! Docker, because the server needs TLS settings. Each run makes new certificates.
#![cfg(feature = "docker-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::path::PathBuf;

use aegis_bus::{BusConfig, NatsBus};
use aegis_contracts::Error;
use tempfile::TempDir;

use support::nats_server::{CONFIG_DIRECTORY, NatsServer, ServerOptions, unique_token};
use support::next_text;
use support::tls::Authority;

const UNTRUSTED_SERVER: &str =
    "connect to NATS: the TLS handshake failed: invalid peer certificate: UnknownIssuer";

/// The certificates of one test: the files for the client, and the files for the server.
struct Certificates {
    /// Holds the client files until the test ends.
    _directory: TempDir,
    /// The authority that signed the server certificate.
    ca: PathBuf,
    /// An authority that signed no certificate of the server.
    other_ca: PathBuf,
    /// A client certificate from the authority of the server, and its key.
    client: (PathBuf, PathBuf),
    /// A client certificate from the other authority, and its key.
    other_client: (PathBuf, PathBuf),
    server_files: Vec<(String, Vec<u8>)>,
}

impl Certificates {
    /// Makes certificates for a server on the local host.
    fn new() -> Self {
        Self::for_server_names(&["localhost", "127.0.0.1"])
    }

    /// Makes certificates for a server with these DNS names and IP addresses.
    fn for_server_names(names: &[&str]) -> Self {
        let authority = Authority::new("aegis test authority");
        let other = Authority::new("a different authority");
        let server = authority.server(names);
        let client = authority.client("aegis");
        let other_client = other.client("aegis");

        let directory = tempfile::tempdir().expect("a temporary directory");
        let write = |name: &str, content: &str| {
            let path = directory.path().join(name);
            std::fs::write(&path, content).expect("write a certificate file");
            path
        };
        Self {
            ca: write("ca.pem", &authority.certificate()),
            other_ca: write("other-ca.pem", &other.certificate()),
            client: (
                write("client.pem", &client.certificate),
                write("client.key", &client.key),
            ),
            other_client: (
                write("other-client.pem", &other_client.certificate),
                write("other-client.key", &other_client.key),
            ),
            server_files: vec![
                ("server.pem".to_owned(), server.certificate.into_bytes()),
                ("server.key".to_owned(), server.key.into_bytes()),
                ("ca.pem".to_owned(), authority.certificate().into_bytes()),
            ],
            _directory: directory,
        }
    }

    /// Starts a server with TLS. With `verify_clients`, the server demands a client
    /// certificate from its authority.
    fn start_server(&self, verify_clients: bool) -> NatsServer {
        let config = format!(
            "tls {{\n  cert_file: \"{CONFIG_DIRECTORY}/server.pem\"\n  key_file: \
             \"{CONFIG_DIRECTORY}/server.key\"\n  ca_file: \"{CONFIG_DIRECTORY}/ca.pem\"\n  \
             verify: {verify_clients}\n}}\n"
        );
        NatsServer::start(&ServerOptions {
            config: Some(config),
            files: self.server_files.clone(),
            ..ServerOptions::default()
        })
    }
}

fn config_for(server: &NatsServer, root: &str) -> BusConfig {
    let mut config = BusConfig::default();
    config.nats.urls = vec![server.url().to_owned()];
    config.stream.name = format!("AEGIS_TEST_{root}");
    // The server reserves `max_bytes` of storage for each stream. Keep the test stream small.
    config.stream.max_bytes = 16 * 1024 * 1024;
    config.stream.subjects = vec![format!("{root}.>")];
    config
}

fn connect_error(result: Result<NatsBus, Error>) -> Error {
    result.expect_err("the connection must fail")
}

fn config_message(error: Error) -> String {
    match error {
        Error::Config(message) => message,
        other => panic!("expected Config, got {other:?}"),
    }
}

fn unauthorized_message(error: Error) -> String {
    match error {
        Error::Unauthorized(message) => message,
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

/// Publishes one message and reads it with a durable subscription.
async fn round_trip(config: &BusConfig, root: &str) {
    let bus = aegis_bus::connect(config)
        .await
        .expect("the bus must connect with TLS");
    let subject = format!("{root}.audit");
    bus.publish(&subject, b"record".to_vec()).await.unwrap();
    let mut stream = bus.subscribe(&subject, Some("archive")).await.unwrap();
    assert_eq!(next_text(&mut stream).await, "record");
}

#[tokio::test]
async fn the_client_trusts_only_a_server_from_the_configured_authority() {
    let certificates = Certificates::new();
    let server = certificates.start_server(false);
    let root = unique_token();
    let base = config_for(&server, &root);

    let mut trusted = base.clone();
    trusted.nats.tls.ca_file = Some(certificates.ca.clone());
    round_trip(&trusted, &root).await;
    // The certificate is also valid for the name `localhost`.
    let mut by_name = trusted.clone();
    by_name.nats.urls = vec![server.url().replace("127.0.0.1", "localhost")];
    round_trip(&by_name, &root).await;

    let mut other_authority = base.clone();
    other_authority.nats.tls.ca_file = Some(certificates.other_ca.clone());
    let error = connect_error(NatsBus::connect(&other_authority).await);
    assert_eq!(config_message(error), UNTRUSTED_SERVER);

    // Without `ca_file`, the client trusts only the authorities of the operating system.
    let mut system_authorities = base.clone();
    system_authorities.nats.tls.required = true;
    let error = connect_error(NatsBus::connect(&system_authorities).await);
    assert_eq!(config_message(error), UNTRUSTED_SERVER);

    // With no TLS setting, the client uses TLS because the server demands it. The client
    // does not skip the check of the certificate.
    let error = connect_error(NatsBus::connect(&base).await);
    assert_eq!(config_message(error), UNTRUSTED_SERVER);
}

#[tokio::test]
async fn the_client_checks_the_name_in_the_server_certificate() {
    // The authority is trusted, but the certificate is for a different server.
    let certificates = Certificates::for_server_names(&["nats.example.test"]);
    let server = certificates.start_server(false);
    let root = unique_token();
    let mut config = config_for(&server, &root);
    config.nats.tls.ca_file = Some(certificates.ca.clone());

    let error = connect_error(NatsBus::connect(&config).await);
    let message = config_message(error);
    assert!(
        message.starts_with(
            "connect to NATS: the TLS handshake failed: invalid peer certificate: \
             certificate not valid for name"
        ),
        "{message}"
    );
}

#[tokio::test]
async fn mutual_tls_needs_a_client_certificate_that_the_server_trusts() {
    let certificates = Certificates::new();
    let server = certificates.start_server(true);
    let root = unique_token();
    let mut base = config_for(&server, &root);
    base.nats.tls.ca_file = Some(certificates.ca.clone());

    let error = connect_error(NatsBus::connect(&base).await);
    assert_eq!(
        unauthorized_message(error),
        "connect to NATS: the server did not accept the TLS client certificate (alert \
         CertificateRequired)"
    );

    let mut untrusted_client = base.clone();
    untrusted_client.nats.tls.client_cert_file = Some(certificates.other_client.0.clone());
    untrusted_client.nats.tls.client_key_file = Some(certificates.other_client.1.clone());
    let error = connect_error(NatsBus::connect(&untrusted_client).await);
    assert_eq!(
        unauthorized_message(error),
        "connect to NATS: the server did not accept the TLS client certificate (alert \
         UnknownCA)"
    );

    let mut trusted_client = base.clone();
    trusted_client.nats.tls.client_cert_file = Some(certificates.client.0.clone());
    trusted_client.nats.tls.client_key_file = Some(certificates.client.1.clone());
    round_trip(&trusted_client, &root).await;
}

#[tokio::test]
async fn mandatory_tls_refuses_a_server_that_has_no_tls() {
    let server = NatsServer::start(&ServerOptions::default());
    let root = unique_token();
    let plain = config_for(&server, &root);
    const NOT_TLS: &str = "connect to NATS: the TLS handshake failed: received corrupt message \
                           of type InvalidContentType";

    let mut required = plain.clone();
    required.nats.tls.required = true;
    let error = connect_error(NatsBus::connect(&required).await);
    assert_eq!(config_message(error), NOT_TLS);

    let mut tls_url = plain.clone();
    tls_url.nats.urls = vec![server.url().replace("nats://", "tls://")];
    let error = connect_error(NatsBus::connect(&tls_url).await);
    assert_eq!(config_message(error), NOT_TLS);

    // The same server accepts the connection when TLS is not mandatory.
    round_trip(&plain, &root).await;
}
