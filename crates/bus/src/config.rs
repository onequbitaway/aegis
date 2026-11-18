//! The configuration of the message bus.
//!
//! All structures have defaults. An empty configuration connects to a NATS server on the
//! local host with no credentials. Unknown keys are an error, so a spelling mistake in a
//! security setting cannot go unnoticed.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use secrecy::SecretString;
use serde::Deserialize;

use crate::subject::check_pattern;

/// The largest name of a stream, in bytes.
const MAX_STREAM_NAME_BYTES: usize = 64;
/// The largest number of replicas that JetStream permits.
const MAX_REPLICAS: usize = 5;
/// The smallest age limit that JetStream permits.
const MIN_MAX_AGE: Duration = Duration::from_millis(100);
/// The smallest acknowledgement time. A smaller value causes continuous redelivery.
const MIN_ACK_WAIT: Duration = Duration::from_millis(100);
/// The smallest pull expiry. The heartbeat interval is half of this value.
const MIN_PULL_EXPIRES: Duration = Duration::from_secs(1);
/// The largest number of messages in one pull request.
const MAX_PULL_BATCH: usize = 10_000;

/// The configuration of the message bus.
///
/// The structure has no `Serialize` implementation, because it can hold secrets.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BusConfig {
    /// The bus implementation.
    pub kind: BusKind,
    /// The connection to the NATS servers. The in-process bus ignores this section.
    pub nats: NatsConfig,
    /// The stream that stores the messages.
    pub stream: StreamConfig,
    /// The settings of durable subscriptions. The in-process bus ignores this section.
    pub consumer: ConsumerConfig,
}

impl BusConfig {
    /// Checks the sections that the selected bus implementation uses.
    ///
    /// For [`BusKind::Nats`], the function checks all sections. For [`BusKind::Memory`],
    /// the function checks only the `stream` section.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] with the name of the first setting that is not valid.
    pub fn validate(&self) -> Result<()> {
        match self.kind {
            BusKind::Nats => self.validate_for_nats(),
            BusKind::Memory => self.stream.validate(),
        }
    }

    /// Checks all sections. The NATS bus uses all of them.
    pub(crate) fn validate_for_nats(&self) -> Result<()> {
        self.nats.validate()?;
        self.stream.validate()?;
        self.consumer.validate()
    }
}

/// The bus implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusKind {
    /// NATS JetStream. Messages survive a restart of AEGIS.
    #[default]
    Nats,
    /// A bus in the memory of this process. All messages go away when the process stops.
    Memory,
}

/// The connection to the NATS servers.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NatsConfig {
    /// The server URLs, with the scheme `nats://` or `tls://`. `tls://` makes TLS mandatory.
    ///
    /// Do not put credentials in a URL. Use [`NatsConfig::auth`].
    pub urls: Vec<String>,
    /// The name that the servers show for this connection.
    pub connection_name: String,
    /// The credentials.
    pub auth: NatsAuth,
    /// The TLS settings.
    pub tls: TlsConfig,
    /// The time limit for the first connection.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// The time limit for one request, which includes the wait for a publish acknowledgement.
    #[serde(with = "humantime_serde")]
    pub request_timeout: Duration,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            urls: vec!["nats://127.0.0.1:4222".to_owned()],
            connection_name: "aegis".to_owned(),
            auth: NatsAuth::default(),
            tls: TlsConfig::default(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
        }
    }
}

impl fmt::Debug for NatsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let urls: Vec<String> = self.urls.iter().map(|url| redact_user_info(url)).collect();
        formatter
            .debug_struct("NatsConfig")
            .field("urls", &urls)
            .field("connection_name", &self.connection_name)
            .field("auth", &self.auth)
            .field("tls", &self.tls)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl NatsConfig {
    fn validate(&self) -> Result<()> {
        self.server_addresses()?;
        if self.connect_timeout.is_zero() {
            return Err(config_error("nats.connect_timeout must be more than zero"));
        }
        if self.request_timeout.is_zero() {
            return Err(config_error("nats.request_timeout must be more than zero"));
        }
        if let NatsAuth::UserPassword { user, .. } = &self.auth
            && user.is_empty()
        {
            return Err(config_error("nats.auth.user must not be empty"));
        }
        self.tls.validate()
    }

    /// Parses the server URLs. An error message never shows a URL, because a URL that is
    /// not valid can contain a password.
    pub(crate) fn server_addresses(&self) -> Result<Vec<async_nats::ServerAddr>> {
        if self.urls.is_empty() {
            return Err(config_error("nats.urls must have one URL or more"));
        }
        self.urls
            .iter()
            .enumerate()
            .map(|(index, url)| {
                let address = async_nats::ServerAddr::from_str(url).map_err(|_| {
                    Error::Config(format!("nats.urls[{index}] is not a valid NATS URL"))
                })?;
                if address.has_user_pass() || address.password().is_some() {
                    return Err(Error::Config(format!(
                        "nats.urls[{index}] has credentials; put credentials in nats.auth"
                    )));
                }
                if address.is_websocket() {
                    return Err(Error::Config(format!(
                        "nats.urls[{index}] must use the scheme nats:// or tls://"
                    )));
                }
                Ok(address)
            })
            .collect()
    }

    /// Returns `true` if the client must refuse a connection that has no TLS.
    pub(crate) fn requires_tls(&self) -> bool {
        self.tls.required
            || self.tls.ca_file.is_some()
            || self.tls.client_cert_file.is_some()
            || self.tls.client_key_file.is_some()
    }
}

/// Replaces the user name and the password of a URL with a fixed text.
fn redact_user_info(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let host = match authority.rsplit_once('@') {
        Some((_, host)) => format!("[REDACTED]@{host}"),
        None => authority.to_owned(),
    };
    match scheme {
        Some(scheme) => format!("{scheme}://{host}{tail}"),
        None => format!("{host}{tail}"),
    }
}

/// The credentials for the NATS servers.
///
/// Select the method with the key `method`. The `Debug` output does not show secrets.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum NatsAuth {
    /// No credentials.
    #[default]
    None,
    /// A user name and a password.
    UserPassword {
        /// The user name.
        user: String,
        /// The password.
        password: SecretString,
    },
    /// A token.
    Token {
        /// The token.
        token: SecretString,
    },
    /// A NATS credentials file, which holds a user JWT and an NKey seed.
    CredentialsFile {
        /// The path of the file.
        path: PathBuf,
    },
}

/// The TLS settings for the NATS connection.
///
/// TLS is mandatory when `required` is `true`, when a file is set, or when a URL has the
/// scheme `tls://`. In all other cases, the client uses TLS only if the server demands it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Refuse a connection that has no TLS.
    pub required: bool,
    /// A PEM file with the certificate authorities to trust. Without it, the client trusts
    /// the certificate authorities of the operating system.
    pub ca_file: Option<PathBuf>,
    /// A PEM file with the client certificate, for mutual TLS.
    pub client_cert_file: Option<PathBuf>,
    /// A PEM file with the private key of the client certificate.
    pub client_key_file: Option<PathBuf>,
}

impl TlsConfig {
    fn validate(&self) -> Result<()> {
        match (&self.client_cert_file, &self.client_key_file) {
            (Some(_), None) => Err(config_error(
                "nats.tls.client_cert_file needs nats.tls.client_key_file",
            )),
            (None, Some(_)) => Err(config_error(
                "nats.tls.client_key_file needs nats.tls.client_cert_file",
            )),
            _ => Ok(()),
        }
    }
}

/// Where JetStream keeps the messages of the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageKind {
    /// On the disk of the NATS server. Messages survive a restart of the server.
    #[default]
    File,
    /// In the memory of the NATS server. A restart of the server deletes the stream.
    Memory,
}

/// The stream that stores the messages.
///
/// The in-process bus uses `subjects`, `max_age`, and `max_bytes`, and ignores the other
/// settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StreamConfig {
    /// The name of the JetStream stream.
    pub name: String,
    /// The subjects that the stream stores. A publish to a different subject is an error.
    pub subjects: Vec<String>,
    /// The bus deletes a message that is older than this value. Zero means no age limit.
    #[serde(with = "humantime_serde")]
    pub max_age: Duration,
    /// When the stream is larger than this number of bytes, the bus deletes the oldest
    /// messages. Zero means no size limit.
    pub max_bytes: u64,
    /// Where JetStream keeps the messages.
    pub storage: StorageKind,
    /// The number of servers that keep a copy of the stream, from 1 to 5.
    pub replicas: usize,
    /// Let AEGIS create and update the stream. Set this to `false` when the NATS account
    /// of AEGIS has no permission to change streams. An administrator must then create
    /// the stream.
    pub manage: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            name: "AEGIS".to_owned(),
            subjects: vec!["aegis.>".to_owned()],
            max_age: Duration::from_secs(7 * 24 * 60 * 60),
            max_bytes: 1024 * 1024 * 1024,
            storage: StorageKind::File,
            replicas: 1,
            manage: true,
        }
    }
}

impl StreamConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let has_valid_characters = self
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if self.name.is_empty() || self.name.len() > MAX_STREAM_NAME_BYTES || !has_valid_characters
        {
            return Err(Error::Config(format!(
                "stream.name must have 1 to {MAX_STREAM_NAME_BYTES} characters from `A-Z`, \
                 `a-z`, `0-9`, `-`, and `_`"
            )));
        }
        if self.subjects.is_empty() {
            return Err(config_error(
                "stream.subjects must have one subject or more",
            ));
        }
        for (index, subject) in self.subjects.iter().enumerate() {
            check_pattern(subject).map_err(|error| {
                Error::Config(format!("stream.subjects[{index}] is not valid: {error}"))
            })?;
        }
        if !self.max_age.is_zero() && self.max_age < MIN_MAX_AGE {
            return Err(config_error(
                "stream.max_age must be zero (no limit) or 100 milliseconds or more",
            ));
        }
        if i64::try_from(self.max_bytes).is_err() {
            return Err(config_error("stream.max_bytes is too large"));
        }
        if self.replicas == 0 || self.replicas > MAX_REPLICAS {
            return Err(Error::Config(format!(
                "stream.replicas must be from 1 to {MAX_REPLICAS}"
            )));
        }
        Ok(())
    }

    /// Returns the age limit, or `None` for no limit.
    pub(crate) fn age_limit(&self) -> Option<Duration> {
        (!self.max_age.is_zero()).then_some(self.max_age)
    }

    /// Returns the size limit in bytes, or `None` for no limit.
    pub(crate) fn byte_limit(&self) -> Option<u64> {
        (self.max_bytes != 0).then_some(self.max_bytes)
    }
}

/// The settings of durable subscriptions on NATS.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsumerConfig {
    /// The server sends a message again when the bus does not acknowledge it in this time.
    /// Set this value larger than the longest time that a subscriber uses for one message.
    #[serde(with = "humantime_serde")]
    pub ack_wait: Duration,
    /// The number of messages that a durable subscription takes from the server in one
    /// request. The default is 1. Refer to the README before you increase it.
    pub pull_batch: usize,
    /// The life of one pull request. The server sends a heartbeat at half of this interval.
    /// A smaller value finds a lost connection sooner.
    #[serde(with = "humantime_serde")]
    pub pull_expires: Duration,
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            ack_wait: Duration::from_secs(30),
            pull_batch: 1,
            pull_expires: Duration::from_secs(10),
        }
    }
}

impl ConsumerConfig {
    fn validate(&self) -> Result<()> {
        if self.ack_wait < MIN_ACK_WAIT {
            return Err(config_error(
                "consumer.ack_wait must be 100 milliseconds or more",
            ));
        }
        if self.pull_batch == 0 || self.pull_batch > MAX_PULL_BATCH {
            return Err(Error::Config(format!(
                "consumer.pull_batch must be from 1 to {MAX_PULL_BATCH}"
            )));
        }
        if self.pull_expires < MIN_PULL_EXPIRES {
            return Err(config_error(
                "consumer.pull_expires must be 1 second or more",
            ));
        }
        Ok(())
    }
}

fn config_error(message: &str) -> Error {
    Error::Config(message.to_owned())
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn parse(text: &str) -> BusConfig {
        toml::from_str(text).expect("the configuration must parse")
    }

    fn config_message(config: &BusConfig) -> String {
        match config.validate() {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_configuration_has_the_documented_defaults() {
        let config = parse("");
        assert_eq!(config.kind, BusKind::Nats);
        assert_eq!(config.nats.urls, ["nats://127.0.0.1:4222"]);
        assert_eq!(config.nats.connection_name, "aegis");
        assert!(matches!(config.nats.auth, NatsAuth::None));
        assert_eq!(config.nats.tls, TlsConfig::default());
        assert!(!config.nats.requires_tls());
        assert_eq!(config.nats.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.nats.request_timeout, Duration::from_secs(5));
        assert_eq!(
            config.stream,
            StreamConfig {
                name: "AEGIS".to_owned(),
                subjects: vec!["aegis.>".to_owned()],
                max_age: Duration::from_secs(604_800),
                max_bytes: 1_073_741_824,
                storage: StorageKind::File,
                replicas: 1,
                manage: true,
            }
        );
        assert_eq!(
            config.consumer,
            ConsumerConfig {
                ack_wait: Duration::from_secs(30),
                pull_batch: 1,
                pull_expires: Duration::from_secs(10),
            }
        );
        config.validate().expect("the defaults must be valid");
    }

    #[test]
    fn the_first_example_of_the_readme_has_the_default_values() {
        let readme = include_str!("../README.md");
        let (_, after_start) = readme
            .split_once("```toml\n")
            .expect("the README must have a TOML example");
        let (example, _) = after_start
            .split_once("```")
            .expect("the TOML example must end");
        let config = parse(example);
        let defaults = BusConfig::default();
        assert_eq!(config.kind, defaults.kind);
        assert_eq!(config.nats.urls, defaults.nats.urls);
        assert_eq!(config.nats.connection_name, defaults.nats.connection_name);
        assert_eq!(config.nats.connect_timeout, defaults.nats.connect_timeout);
        assert_eq!(config.nats.request_timeout, defaults.nats.request_timeout);
        assert!(matches!(config.nats.auth, NatsAuth::None));
        assert_eq!(config.nats.tls, defaults.nats.tls);
        assert_eq!(config.stream, defaults.stream);
        assert_eq!(config.consumer, defaults.consumer);
    }

    #[test]
    fn a_full_configuration_parses() {
        let config = parse(
            r#"
            kind = "nats"

            [nats]
            urls = ["tls://nats-1.example.com:4222", "tls://nats-2.example.com:4222"]
            connection_name = "aegis-prod"
            connect_timeout = "3s"
            request_timeout = "750ms"

            [nats.auth]
            method = "user_password"
            user = "aegis"
            password = "correct horse"

            [nats.tls]
            required = true
            ca_file = "/etc/aegis/nats-ca.pem"
            client_cert_file = "/etc/aegis/nats-client.pem"
            client_key_file = "/etc/aegis/nats-client.key"

            [stream]
            name = "AEGIS_PROD"
            subjects = ["aegis.>", "audit.>"]
            max_age = "36h"
            max_bytes = 5368709120
            storage = "memory"
            replicas = 3
            manage = false

            [consumer]
            ack_wait = "2m"
            pull_batch = 50
            pull_expires = "5s"
            "#,
        );
        assert_eq!(config.nats.urls.len(), 2);
        assert_eq!(config.nats.connection_name, "aegis-prod");
        assert_eq!(config.nats.connect_timeout, Duration::from_secs(3));
        assert_eq!(config.nats.request_timeout, Duration::from_millis(750));
        match &config.nats.auth {
            NatsAuth::UserPassword { user, password } => {
                assert_eq!(user, "aegis");
                assert_eq!(password.expose_secret(), "correct horse");
            }
            other => panic!("expected a user name and a password, got {other:?}"),
        }
        assert_eq!(
            config.nats.tls,
            TlsConfig {
                required: true,
                ca_file: Some(PathBuf::from("/etc/aegis/nats-ca.pem")),
                client_cert_file: Some(PathBuf::from("/etc/aegis/nats-client.pem")),
                client_key_file: Some(PathBuf::from("/etc/aegis/nats-client.key")),
            }
        );
        assert_eq!(
            config.stream,
            StreamConfig {
                name: "AEGIS_PROD".to_owned(),
                subjects: vec!["aegis.>".to_owned(), "audit.>".to_owned()],
                max_age: Duration::from_secs(36 * 60 * 60),
                max_bytes: 5_368_709_120,
                storage: StorageKind::Memory,
                replicas: 3,
                manage: false,
            }
        );
        assert_eq!(
            config.consumer,
            ConsumerConfig {
                ack_wait: Duration::from_secs(120),
                pull_batch: 50,
                pull_expires: Duration::from_secs(5),
            }
        );
        config.validate().expect("the configuration must be valid");
    }

    #[test]
    fn the_memory_kind_needs_no_other_setting() {
        let config = parse(r#"kind = "memory""#);
        assert_eq!(config.kind, BusKind::Memory);
        config.validate().expect("the configuration must be valid");
    }

    #[test]
    fn the_memory_kind_checks_only_the_stream_section() {
        let mut config = parse(r#"kind = "memory""#);
        config.nats.urls = Vec::new();
        config.consumer.pull_batch = 0;
        config
            .validate()
            .expect("the in-process bus does not use these sections");

        config.stream.subjects = Vec::new();
        assert_eq!(
            config_message(&config),
            "stream.subjects must have one subject or more"
        );

        // The NATS bus uses all sections.
        config.kind = BusKind::Nats;
        assert_eq!(
            config_message(&config),
            "nats.urls must have one URL or more"
        );
    }

    #[test]
    fn the_token_and_the_credentials_file_methods_parse() {
        let config = parse("[nats.auth]\nmethod = \"token\"\ntoken = \"s3cr3t-token\"");
        match &config.nats.auth {
            NatsAuth::Token { token } => assert_eq!(token.expose_secret(), "s3cr3t-token"),
            other => panic!("expected a token, got {other:?}"),
        }
        let config =
            parse("[nats.auth]\nmethod = \"credentials_file\"\npath = \"/run/aegis.creds\"");
        match &config.nats.auth {
            NatsAuth::CredentialsFile { path } => {
                assert_eq!(path, &PathBuf::from("/run/aegis.creds"));
            }
            other => panic!("expected a credentials file, got {other:?}"),
        }
    }

    #[test]
    fn debug_output_does_not_show_secrets() {
        let mut config = parse(
            "[nats.auth]\nmethod = \"user_password\"\nuser = \"aegis\"\npassword = \"hunter2-password\"",
        );
        config.nats.urls = vec![
            "nats://admin:url-password@nats.example.com:4222/path".to_owned(),
            "other-user:other-password@10.0.0.1:4222".to_owned(),
            "nats://plain.example.com:4222".to_owned(),
        ];
        let debug = format!("{config:?}");
        assert!(!debug.contains("hunter2-password"), "{debug}");
        assert!(!debug.contains("url-password"), "{debug}");
        assert!(!debug.contains("other-password"), "{debug}");
        assert!(!debug.contains("admin"), "{debug}");
        assert!(
            debug.contains("nats://[REDACTED]@nats.example.com:4222/path"),
            "{debug}"
        );
        assert!(debug.contains("[REDACTED]@10.0.0.1:4222"), "{debug}");
        assert!(debug.contains("nats://plain.example.com:4222"), "{debug}");

        let token = parse("[nats.auth]\nmethod = \"token\"\ntoken = \"s3cr3t-token\"");
        let debug = format!("{token:?}");
        assert!(!debug.contains("s3cr3t-token"), "{debug}");
    }

    #[test]
    fn an_unknown_key_is_an_error() {
        for text in [
            "kimd = \"memory\"",
            "[nats]\nurl = \"nats://127.0.0.1:4222\"",
            "[nats.tls]\nrequird = true",
            "[nats.auth]\nmethod = \"token\"\ntoken = \"t\"\nuser = \"u\"",
            "[stream]\nmax_msgs = 5",
            "[consumer]\nackwait = \"1s\"",
        ] {
            let error = toml::from_str::<BusConfig>(text).expect_err(text);
            assert!(
                error.to_string().contains("unknown field"),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn an_unknown_kind_or_method_is_an_error() {
        let error = toml::from_str::<BusConfig>("kind = \"kafka\"").expect_err("kind");
        assert!(
            error.to_string().contains("unknown variant `kafka`"),
            "{error}"
        );
        let error =
            toml::from_str::<BusConfig>("[nats.auth]\nmethod = \"basic\"").expect_err("method");
        assert!(
            error.to_string().contains("unknown variant `basic`"),
            "{error}"
        );
        let error = toml::from_str::<BusConfig>("[nats.auth]\nuser = \"u\"").expect_err("method");
        assert!(
            error.to_string().contains("missing field `method`"),
            "{error}"
        );
    }

    #[test]
    fn a_url_that_is_not_valid_is_an_error_that_does_not_show_the_url() {
        let mut config = BusConfig::default();
        config.nats.urls = vec![
            "nats://127.0.0.1:4222".to_owned(),
            "nats://user:secret-in-url@[bad".to_owned(),
        ];
        assert_eq!(
            config_message(&config),
            "nats.urls[1] is not a valid NATS URL"
        );

        config.nats.urls = vec!["nats://user:secret-in-url@nats.example.com:4222".to_owned()];
        assert_eq!(
            config_message(&config),
            "nats.urls[0] has credentials; put credentials in nats.auth"
        );

        config.nats.urls = vec!["wss://nats.example.com:443".to_owned()];
        assert_eq!(
            config_message(&config),
            "nats.urls[0] must use the scheme nats:// or tls://"
        );

        config.nats.urls = vec!["http://nats.example.com".to_owned()];
        assert_eq!(
            config_message(&config),
            "nats.urls[0] is not a valid NATS URL"
        );

        config.nats.urls = Vec::new();
        assert_eq!(
            config_message(&config),
            "nats.urls must have one URL or more"
        );
    }

    #[test]
    fn each_setting_out_of_range_is_an_error_with_its_name() {
        type Change = fn(&mut BusConfig);
        let cases: [(Change, &str); 14] = [
            (
                |c| c.nats.connect_timeout = Duration::ZERO,
                "nats.connect_timeout",
            ),
            (
                |c| c.nats.request_timeout = Duration::ZERO,
                "nats.request_timeout",
            ),
            (
                |c| {
                    c.nats.auth = NatsAuth::UserPassword {
                        user: String::new(),
                        password: SecretString::from("p"),
                    };
                },
                "nats.auth.user",
            ),
            (
                |c| c.nats.tls.client_cert_file = Some(PathBuf::from("client.pem")),
                "nats.tls.client_cert_file needs nats.tls.client_key_file",
            ),
            (
                |c| c.nats.tls.client_key_file = Some(PathBuf::from("client.key")),
                "nats.tls.client_key_file needs nats.tls.client_cert_file",
            ),
            (|c| c.stream.name = String::new(), "stream.name"),
            (|c| c.stream.name = "AEGIS.PROD".to_owned(), "stream.name"),
            (
                |c| c.stream.subjects = Vec::new(),
                "stream.subjects must have",
            ),
            (
                |c| c.stream.subjects = vec!["aegis.>".to_owned(), "aegis.>.x".to_owned()],
                "stream.subjects[1] is not valid",
            ),
            (
                |c| c.stream.max_age = Duration::from_millis(99),
                "stream.max_age",
            ),
            (|c| c.stream.max_bytes = u64::MAX, "stream.max_bytes"),
            (
                |c| c.stream.replicas = 0,
                "stream.replicas must be from 1 to 5",
            ),
            (
                |c| c.stream.replicas = 6,
                "stream.replicas must be from 1 to 5",
            ),
            (
                |c| c.consumer.ack_wait = Duration::from_millis(99),
                "consumer.ack_wait",
            ),
        ];
        for (change, expected) in cases {
            let mut config = BusConfig::default();
            change(&mut config);
            let message = config_message(&config);
            assert!(
                message.contains(expected),
                "expected {expected:?} in {message:?}"
            );
        }
    }

    #[test]
    fn the_pull_settings_have_limits() {
        type Change = fn(&mut BusConfig);
        let cases: [(Change, &str); 3] = [
            (
                |c| c.consumer.pull_batch = 0,
                "consumer.pull_batch must be from 1 to 10000",
            ),
            (
                |c| c.consumer.pull_batch = 10_001,
                "consumer.pull_batch must be from 1 to 10000",
            ),
            (
                |c| c.consumer.pull_expires = Duration::from_millis(999),
                "consumer.pull_expires must be 1 second or more",
            ),
        ];
        for (change, expected) in cases {
            let mut config = BusConfig::default();
            change(&mut config);
            assert_eq!(config_message(&config), expected);
        }
    }

    #[test]
    fn zero_means_no_retention_limit() {
        let config = parse("[stream]\nmax_age = \"0s\"\nmax_bytes = 0");
        config.validate().expect("zero limits must be valid");
        assert_eq!(config.stream.age_limit(), None);
        assert_eq!(config.stream.byte_limit(), None);

        let limited = BusConfig::default();
        assert_eq!(
            limited.stream.age_limit(),
            Some(Duration::from_secs(604_800))
        );
        assert_eq!(limited.stream.byte_limit(), Some(1_073_741_824));
    }

    #[test]
    fn a_certificate_file_makes_tls_mandatory() {
        let config = parse("[nats.tls]\nca_file = \"/etc/aegis/ca.pem\"");
        assert!(!config.nats.tls.required);
        assert!(config.nats.requires_tls());

        let config = parse("[nats.tls]\nrequired = true");
        assert!(config.nats.requires_tls());
    }
}
