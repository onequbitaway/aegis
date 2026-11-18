//! The configuration of the store.

use std::str::FromStr;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

const DEFAULT_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_ACQUIRE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_STATEMENT_TIMEOUT_SECONDS: u64 = 30;
const APPLICATION_NAME: &str = "aegis-storage";

/// The URL parameters that the store accepts.
///
/// The database driver writes each parameter that it does not know to the log. The store
/// rejects such a parameter first, so that no part of the URL can go to the log.
const URL_PARAMETERS: &[&str] = &[
    "sslmode",
    "sslrootcert",
    "sslcert",
    "sslkey",
    "application_name",
    "options",
    "statement-cache-capacity",
];

/// The configuration of [`PgStore`](crate::PgStore).
///
/// The `Debug` output does not show the database URL.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// The database URL, for example `postgres://user:password@host:5432/aegis`.
    ///
    /// The URL is a secret. Add `?sslmode=verify-full` to require TLS with a checked
    /// server certificate. Add `&sslrootcert=/path/ca.pem` for a private certificate
    /// authority.
    pub url: SecretString,
    /// The largest number of open connections. The default is 10.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// The number of connections that the pool keeps open. The default is 0.
    #[serde(default)]
    pub min_connections: u32,
    /// The time to wait for a connection, in seconds. The default is 10.
    #[serde(default = "default_acquire_timeout_seconds")]
    pub acquire_timeout_seconds: u64,
    /// The time limit of one statement, in seconds. The default is 30. The value 0
    /// sets no limit.
    #[serde(default = "default_statement_timeout_seconds")]
    pub statement_timeout_seconds: u64,
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

fn default_acquire_timeout_seconds() -> u64 {
    DEFAULT_ACQUIRE_TIMEOUT_SECONDS
}

fn default_statement_timeout_seconds() -> u64 {
    DEFAULT_STATEMENT_TIMEOUT_SECONDS
}

impl StorageConfig {
    /// Makes a configuration with the default pool settings.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: SecretString::from(url.into()),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            min_connections: 0,
            acquire_timeout_seconds: DEFAULT_ACQUIRE_TIMEOUT_SECONDS,
            statement_timeout_seconds: DEFAULT_STATEMENT_TIMEOUT_SECONDS,
        }
    }

    /// Returns the time to wait for a connection.
    #[must_use]
    pub fn acquire_timeout(&self) -> Duration {
        Duration::from_secs(self.acquire_timeout_seconds)
    }

    /// Checks the configuration and makes the connection options.
    ///
    /// No error from this function contains a part of the URL.
    pub(crate) fn connect_options(&self) -> Result<PgConnectOptions> {
        if self.max_connections == 0 {
            return Err(Error::Config(
                "storage: max_connections must be 1 or more".to_owned(),
            ));
        }
        if self.min_connections > self.max_connections {
            return Err(Error::Config(
                "storage: min_connections must not be larger than max_connections".to_owned(),
            ));
        }
        if self.acquire_timeout_seconds == 0 {
            return Err(Error::Config(
                "storage: acquire_timeout_seconds must be 1 or more".to_owned(),
            ));
        }

        let url = url::Url::parse(self.url.expose_secret()).map_err(|_| invalid_url())?;
        if !matches!(url.scheme(), "postgres" | "postgresql") {
            return Err(Error::Config(
                "storage: the database URL must start with postgres:// or postgresql://".to_owned(),
            ));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(Error::Config(
                "storage: the database URL must have a host".to_owned(),
            ));
        }
        for (key, _) in url.query_pairs() {
            if !URL_PARAMETERS.contains(&key.as_ref()) {
                return Err(Error::Config(format!(
                    "storage: the database URL has a parameter that is not supported. \
                     The supported parameters are: {}",
                    URL_PARAMETERS.join(", ")
                )));
            }
        }

        let options =
            PgConnectOptions::from_str(self.url.expose_secret()).map_err(|_| invalid_url())?;
        Ok(match options.get_application_name() {
            Some(_) => options,
            None => options.application_name(APPLICATION_NAME),
        })
    }
}

fn invalid_url() -> Error {
    Error::Config(
        "storage: the database URL is not valid. \
         Use the form postgres://user:password@host:port/database"
            .to_owned(),
    )
}

/// Returns `true` if the connection checks the certificate of the server.
pub(crate) fn verifies_server(options: &PgConnectOptions) -> bool {
    matches!(
        options.get_ssl_mode(),
        PgSslMode::VerifyCa | PgSslMode::VerifyFull
    )
}

/// Returns `true` if the server is on this host.
pub(crate) fn is_local(options: &PgConnectOptions) -> bool {
    options.get_socket().is_some()
        || matches!(
            options.get_host(),
            "localhost" | "127.0.0.1" | "::1" | "[::1]"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_URL: &str = "postgres://aegis:hunter2-secret@db.internal.example:6543/aegis";

    fn config_error(config: &StorageConfig) -> String {
        match config.connect_options() {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_url_gives_the_connection_options() {
        let options = StorageConfig::new(format!("{SECRET_URL}?sslmode=verify-full"))
            .connect_options()
            .unwrap();
        assert_eq!(options.get_host(), "db.internal.example");
        assert_eq!(options.get_port(), 6543);
        assert_eq!(options.get_username(), "aegis");
        assert_eq!(options.get_database(), Some("aegis"));
        assert_eq!(options.get_application_name(), Some("aegis-storage"));
        assert!(verifies_server(&options));
        assert!(!is_local(&options));
    }

    #[test]
    fn the_url_keeps_its_own_application_name() {
        let options = StorageConfig::new(format!("{SECRET_URL}?application_name=console"))
            .connect_options()
            .unwrap();
        assert_eq!(options.get_application_name(), Some("console"));
    }

    #[test]
    fn a_url_without_sslmode_does_not_verify_the_server() {
        let options = StorageConfig::new("postgres://aegis:pw@localhost/aegis?sslmode=require")
            .connect_options()
            .unwrap();
        assert!(!verifies_server(&options));
        assert!(is_local(&options));
    }

    #[test]
    fn debug_output_does_not_show_the_url() {
        let text = format!("{:?}", StorageConfig::new(SECRET_URL));
        assert!(text.contains("REDACTED"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("db.internal.example"), "{text}");
    }

    #[test]
    fn no_configuration_error_contains_a_part_of_the_url() {
        let bad_urls = [
            // Not a URL.
            "aegis:hunter2-secret@db.internal.example".to_owned(),
            // A port that is not a number.
            "postgres://aegis:hunter2-secret@db.internal.example:port/aegis".to_owned(),
            // A scheme for a different database.
            "mysql://aegis:hunter2-secret@db.internal.example/aegis".to_owned(),
            // A parameter that the driver would write to the log.
            format!("{SECRET_URL}?passwrod=hunter2-secret"),
            // A value that the driver cannot read.
            format!("{SECRET_URL}?sslmode=hunter2-secret"),
            // No host.
            "postgres:///aegis?options=hunter2-secret".to_owned(),
        ];
        for url in bad_urls {
            let message = config_error(&StorageConfig::new(url.clone()));
            assert!(!message.contains("hunter2"), "{url} -> {message}");
            assert!(!message.contains("db.internal"), "{url} -> {message}");
            assert!(
                message.starts_with("storage: the database URL"),
                "{message}"
            );
        }
    }

    #[test]
    fn pool_limits_are_checked() {
        let mut config = StorageConfig::new(SECRET_URL);
        config.max_connections = 0;
        assert_eq!(
            config_error(&config),
            "storage: max_connections must be 1 or more"
        );

        let mut config = StorageConfig::new(SECRET_URL);
        config.min_connections = 11;
        assert_eq!(
            config_error(&config),
            "storage: min_connections must not be larger than max_connections"
        );

        let mut config = StorageConfig::new(SECRET_URL);
        config.acquire_timeout_seconds = 0;
        assert_eq!(
            config_error(&config),
            "storage: acquire_timeout_seconds must be 1 or more"
        );
    }

    #[test]
    fn deserialization_uses_the_defaults_and_rejects_unknown_fields() {
        let config: StorageConfig =
            serde_json::from_value(serde_json::json!({ "url": SECRET_URL })).unwrap();
        assert_eq!(config.url.expose_secret(), SECRET_URL);
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 0);
        assert_eq!(config.acquire_timeout(), Duration::from_secs(10));
        assert_eq!(config.statement_timeout_seconds, 30);

        let error = serde_json::from_value::<StorageConfig>(
            serde_json::json!({ "url": SECRET_URL, "pool": 3 }),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("unknown field `pool`"),
            "{error}"
        );
    }
}
