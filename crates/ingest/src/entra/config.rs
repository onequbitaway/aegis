//! The configuration of the Entra ID source connector.

use std::net::IpAddr;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use super::client::Feed;
use crate::check_configured_name;

/// The largest page size that Microsoft Graph permits for the log endpoints.
const MAX_PAGE_SIZE: u32 = 1000;

/// The configuration of an [`EntraSource`](super::EntraSource).
///
/// The application registration needs the Microsoft Graph application permission
/// `AuditLog.Read.All`. The connector only reads.
///
/// Set the client secret in `client_secret_env` (the name of an environment variable) or in
/// `client_secret`. Prefer the environment variable, so that the secret is not in a file.
///
/// ```toml
/// name = "entra-prod"
/// tenant_id = "00000000-0000-0000-0000-000000000000"
/// client_id = "11111111-1111-1111-1111-111111111111"
/// client_secret_env = "AEGIS_ENTRA_CLIENT_SECRET"
/// poll_interval = "30s"
/// lookback = "5m"
/// service_principal_sign_ins = true
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntraConfig {
    /// The name of the connector instance. Events go to `aegis.events.{name}`.
    pub name: String,
    /// The tenant to read: a tenant GUID or a verified domain name.
    pub tenant_id: String,
    /// The application (client) identifier of the application registration.
    pub client_id: String,
    /// The client secret. `Debug` does not print it.
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// The name of the environment variable that holds the client secret.
    #[serde(default)]
    pub client_secret_env: Option<String>,
    /// The base URL of the token service. Change it for a national cloud.
    ///
    /// The default is `https://login.microsoftonline.com`.
    #[serde(default = "default_login_base")]
    pub login_base: String,
    /// The base URL of Microsoft Graph. Change it for a national cloud.
    ///
    /// The default is `https://graph.microsoft.com`.
    #[serde(default = "default_graph_base")]
    pub graph_base: String,
    /// The OAuth scope of the token. The default is `{graph_base}/.default`.
    #[serde(default)]
    pub scope: Option<String>,
    /// The time between two reads of the live stream. The default is 30 seconds.
    #[serde(default = "default_poll_interval", with = "humantime_serde")]
    pub poll_interval: Duration,
    /// How far before the newest record each read starts. The default is 5 minutes.
    ///
    /// Entra ID can add a record to the log some minutes after the time of the record. The
    /// connector reads this period again and removes the records that it already emitted.
    /// The value must be a whole number of seconds.
    #[serde(default = "default_lookback", with = "humantime_serde")]
    pub lookback: Duration,
    /// The longest time range of one read. The default is 1 hour.
    ///
    /// After a long stop, the connector reads the missed time in ranges of this length.
    /// The value must be a whole number of seconds and more than `lookback`.
    #[serde(default = "default_max_window", with = "humantime_serde")]
    pub max_window: Duration,
    /// The time limit of one HTTP request. The default is 30 seconds.
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,
    /// The longest `Retry-After` delay that the connector waits for. The default is 5
    /// minutes. A longer delay is an [`Error::RateLimited`] immediately. The connector
    /// then sends no request to Microsoft Graph until the delay is over, for one hour at
    /// most.
    #[serde(default = "default_max_retry_after", with = "humantime_serde")]
    pub max_retry_after: Duration,
    /// How many times the connector waits for `Retry-After` and sends one request again.
    /// The default is 3.
    #[serde(default = "default_rate_limit_retries")]
    pub rate_limit_retries: u32,
    /// The number of records in one page, from 1 to 1000. The default is 500.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Read the user sign-in log (`v1.0/auditLogs/signIns`). The default is `true`.
    #[serde(default = "default_true")]
    pub sign_ins: bool,
    /// Read the service principal sign-in log (`beta/auditLogs/signIns` with a filter).
    /// The default is `false`, because the endpoint is a beta endpoint.
    #[serde(default)]
    pub service_principal_sign_ins: bool,
    /// Read the directory audit log (`v1.0/auditLogs/directoryAudits`). The default is
    /// `true`.
    #[serde(default = "default_true")]
    pub directory_audits: bool,
}

fn default_login_base() -> String {
    "https://login.microsoftonline.com".to_owned()
}

fn default_graph_base() -> String {
    "https://graph.microsoft.com".to_owned()
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_lookback() -> Duration {
    Duration::from_secs(5 * 60)
}

fn default_max_window() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_max_retry_after() -> Duration {
    Duration::from_secs(5 * 60)
}

fn default_rate_limit_retries() -> u32 {
    3
}

fn default_page_size() -> u32 {
    500
}

fn default_true() -> bool {
    true
}

impl EntraConfig {
    /// Makes a configuration with the default values for the global Microsoft cloud.
    pub fn new(
        name: impl Into<String>,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: SecretString,
    ) -> Self {
        Self {
            name: name.into(),
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            client_secret: Some(client_secret),
            client_secret_env: None,
            login_base: default_login_base(),
            graph_base: default_graph_base(),
            scope: None,
            poll_interval: default_poll_interval(),
            lookback: default_lookback(),
            max_window: default_max_window(),
            request_timeout: default_request_timeout(),
            max_retry_after: default_max_retry_after(),
            rate_limit_retries: default_rate_limit_retries(),
            page_size: default_page_size(),
            sign_ins: true,
            service_principal_sign_ins: false,
            directory_audits: true,
        }
    }

    /// Checks the configuration and reads the client secret.
    ///
    /// `environment` returns the value of an environment variable.
    pub(crate) fn validate(
        &self,
        environment: impl Fn(&str) -> Option<String>,
    ) -> Result<Settings> {
        let invalid =
            |problem: String| Error::Config(format!("entra source {}: {problem}", self.name));
        check_configured_name(&self.name)?;

        let tenant_id = self.tenant_id.trim();
        let is_path_safe = |character: char| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        };
        if tenant_id.is_empty() || !tenant_id.chars().all(is_path_safe) || tenant_id.contains("..")
        {
            return Err(invalid(
                "tenant_id must be a tenant GUID or a domain name".to_owned(),
            ));
        }
        let client_id = self.client_id.trim();
        if client_id.is_empty() {
            return Err(invalid("client_id is empty".to_owned()));
        }

        let client_secret =
            match (&self.client_secret, &self.client_secret_env) {
                (Some(_), Some(_)) => {
                    return Err(invalid(
                        "set client_secret or client_secret_env, not the two".to_owned(),
                    ));
                }
                (Some(secret), None) => secret.clone(),
                (None, Some(variable)) => environment(variable)
                    .map(SecretString::from)
                    .ok_or_else(|| {
                        invalid(format!("the environment variable {variable} is not set"))
                    })?,
                (None, None) => {
                    return Err(invalid("set client_secret_env or client_secret".to_owned()));
                }
            };
        if client_secret.expose_secret().trim().is_empty() {
            return Err(invalid("the client secret is empty".to_owned()));
        }

        let login_base = base_url(&self.login_base)
            .map_err(|problem| invalid(format!("login_base {problem}")))?;
        let graph_base = base_url(&self.graph_base)
            .map_err(|problem| invalid(format!("graph_base {problem}")))?;
        let token_url = Url::parse(&format!("{login_base}/{tenant_id}/oauth2/v2.0/token"))
            .map_err(|error| invalid(format!("the token URL is not valid: {error}")))?;
        let graph_origin = Url::parse(&graph_base)
            .map_err(|error| invalid(format!("graph_base is not valid: {error}")))?;
        let scope = match self.scope.as_deref().map(str::trim) {
            Some(scope) if !scope.is_empty() => scope.to_owned(),
            _ => format!("{graph_base}/.default"),
        };

        if self.poll_interval.is_zero() {
            return Err(invalid("poll_interval must be more than zero".to_owned()));
        }
        if self.request_timeout.is_zero() {
            return Err(invalid("request_timeout must be more than zero".to_owned()));
        }
        if self.lookback.subsec_nanos() != 0 || self.max_window.subsec_nanos() != 0 {
            return Err(invalid(
                "lookback and max_window must be whole numbers of seconds".to_owned(),
            ));
        }
        if self.max_window <= self.lookback {
            return Err(invalid("max_window must be more than lookback".to_owned()));
        }
        let lookback = chrono::Duration::from_std(self.lookback)
            .map_err(|_| invalid("lookback is too long".to_owned()))?;
        let max_window = chrono::Duration::from_std(self.max_window)
            .map_err(|_| invalid("max_window is too long".to_owned()))?;
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size) {
            return Err(invalid(format!(
                "page_size must be from 1 to {MAX_PAGE_SIZE}"
            )));
        }

        let feeds: Vec<Feed> = [
            (self.sign_ins, Feed::SignIns),
            (
                self.service_principal_sign_ins,
                Feed::ServicePrincipalSignIns,
            ),
            (self.directory_audits, Feed::DirectoryAudits),
        ]
        .into_iter()
        .filter_map(|(enabled, feed)| enabled.then_some(feed))
        .collect();
        if feeds.is_empty() {
            return Err(invalid(
                "enable sign_ins, service_principal_sign_ins, or directory_audits".to_owned(),
            ));
        }

        Ok(Settings {
            name: self.name.clone(),
            tenant_id: tenant_id.to_owned(),
            client_id: client_id.to_owned(),
            client_secret,
            token_url,
            graph_base,
            graph_origin,
            scope,
            poll_interval: self.poll_interval,
            lookback,
            max_window,
            request_timeout: self.request_timeout,
            max_retry_after: self.max_retry_after,
            rate_limit_retries: self.rate_limit_retries,
            page_size: self.page_size,
            feeds,
        })
    }
}

/// The checked configuration that the connector uses.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub name: String,
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub token_url: Url,
    /// The base URL of Microsoft Graph, with no `/` at the end.
    pub graph_base: String,
    pub graph_origin: Url,
    pub scope: String,
    pub poll_interval: Duration,
    pub lookback: chrono::Duration,
    pub max_window: chrono::Duration,
    pub request_timeout: Duration,
    pub max_retry_after: Duration,
    pub rate_limit_retries: u32,
    pub page_size: u32,
    /// The enabled feeds, in the order in which the connector reads them.
    pub feeds: Vec<Feed>,
}

/// Checks a base URL and returns it with no `/` at the end.
///
/// The URL must use HTTPS, because the connector sends the client secret and the token to
/// it. Plain HTTP is permitted only for a loopback address, for local tests.
fn base_url(text: &str) -> std::result::Result<String, String> {
    let url = Url::parse(text.trim()).map_err(|error| format!("is not a valid URL: {error}"))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err("must not have a query or a fragment".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not have a user name or a password".to_owned());
    }
    let Some(host) = url.host_str() else {
        return Err("must have a host".to_owned());
    };
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(host) => {}
        "http" => return Err("must use https (http is only for a loopback address)".to_owned()),
        _ => return Err("must use https".to_owned()),
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn is_loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "00000000-0000-0000-0000-000000000000";
    const CLIENT: &str = "11111111-1111-1111-1111-111111111111";

    fn config() -> EntraConfig {
        EntraConfig::new(
            "entra-test",
            TENANT,
            CLIENT,
            SecretString::from("example-secret"),
        )
    }

    fn no_environment(_: &str) -> Option<String> {
        None
    }

    fn config_error(config: &EntraConfig) -> String {
        match config.validate(no_environment) {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, got {other:?}"),
        }
    }

    #[test]
    fn the_defaults_address_the_global_cloud() {
        let settings = config().validate(no_environment).unwrap();
        assert_eq!(
            settings.token_url.as_str(),
            "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token"
        );
        assert_eq!(settings.graph_base, "https://graph.microsoft.com");
        assert_eq!(settings.scope, "https://graph.microsoft.com/.default");
        assert_eq!(settings.feeds, [Feed::SignIns, Feed::DirectoryAudits]);
        assert_eq!(settings.poll_interval, Duration::from_secs(30));
        assert_eq!(settings.lookback, chrono::Duration::minutes(5));
        assert_eq!(settings.max_window, chrono::Duration::hours(1));
        assert_eq!(settings.page_size, 500);
        assert_eq!(settings.client_secret.expose_secret(), "example-secret");
    }

    #[test]
    fn a_national_cloud_changes_the_token_url_and_the_default_scope() {
        let mut config = config();
        config.login_base = "https://login.microsoftonline.us/".to_owned();
        config.graph_base = "https://graph.microsoft.us/".to_owned();
        config.service_principal_sign_ins = true;
        let settings = config.validate(no_environment).unwrap();
        assert_eq!(
            settings.token_url.as_str(),
            "https://login.microsoftonline.us/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token"
        );
        assert_eq!(settings.scope, "https://graph.microsoft.us/.default");
        assert_eq!(
            settings.feeds,
            [
                Feed::SignIns,
                Feed::ServicePrincipalSignIns,
                Feed::DirectoryAudits
            ]
        );
    }

    #[test]
    fn the_secret_comes_from_the_named_environment_variable() {
        let mut config = config();
        config.client_secret = None;
        config.client_secret_env = Some("AEGIS_TEST_SECRET".to_owned());
        let settings = config
            .validate(|name| (name == "AEGIS_TEST_SECRET").then(|| "from-environment".to_owned()))
            .unwrap();
        assert_eq!(settings.client_secret.expose_secret(), "from-environment");

        let message = config_error(&config);
        assert_eq!(
            message,
            "entra source entra-test: the environment variable AEGIS_TEST_SECRET is not set"
        );
    }

    #[test]
    fn a_missing_an_empty_or_a_double_secret_is_a_configuration_error() {
        let mut none = config();
        none.client_secret = None;
        assert!(config_error(&none).contains("set client_secret_env or client_secret"));

        let mut empty = config();
        empty.client_secret = Some(SecretString::from("  "));
        assert!(config_error(&empty).contains("the client secret is empty"));

        let mut both = config();
        both.client_secret_env = Some("AEGIS_TEST_SECRET".to_owned());
        assert!(config_error(&both).contains("not the two"));
    }

    #[test]
    fn the_configuration_reads_toml_with_the_defaults_for_absent_fields() {
        let config: EntraConfig = toml::from_str(
            r#"
            name = "entra-prod"
            tenant_id = "00000000-0000-0000-0000-000000000000"
            client_id = "11111111-1111-1111-1111-111111111111"
            client_secret_env = "AEGIS_ENTRA_CLIENT_SECRET"
            "#,
        )
        .unwrap();

        assert_eq!(config.name, "entra-prod");
        assert_eq!(config.tenant_id, TENANT);
        assert_eq!(config.client_id, CLIENT);
        assert!(config.client_secret.is_none());
        assert_eq!(
            config.client_secret_env.as_deref(),
            Some("AEGIS_ENTRA_CLIENT_SECRET")
        );
        assert_eq!(config.login_base, "https://login.microsoftonline.com");
        assert_eq!(config.graph_base, "https://graph.microsoft.com");
        assert_eq!(config.scope, None);
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        assert_eq!(config.lookback, Duration::from_secs(300));
        assert_eq!(config.max_window, Duration::from_secs(3600));
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.max_retry_after, Duration::from_secs(300));
        assert_eq!(config.rate_limit_retries, 3);
        assert_eq!(config.page_size, 500);
        assert!(config.sign_ins);
        assert!(!config.service_principal_sign_ins);
        assert!(config.directory_audits);

        let settings = config
            .validate(|name| {
                (name == "AEGIS_ENTRA_CLIENT_SECRET").then(|| "from-environment".to_owned())
            })
            .unwrap();
        assert_eq!(settings.client_secret.expose_secret(), "from-environment");
        assert_eq!(settings.feeds, [Feed::SignIns, Feed::DirectoryAudits]);
    }

    #[test]
    fn the_configuration_reads_each_field_from_toml_with_human_durations() {
        let config: EntraConfig = toml::from_str(
            r#"
            name = "entra-gov"
            tenant_id = "contoso.example"
            client_id = "11111111-1111-1111-1111-111111111111"
            client_secret = "example-secret"
            login_base = "https://login.microsoftonline.us"
            graph_base = "https://graph.microsoft.us"
            scope = "https://graph.microsoft.us/.default"
            poll_interval = "1m"
            lookback = "10m"
            max_window = "2h"
            request_timeout = "15s"
            max_retry_after = "1m 30s"
            rate_limit_retries = 1
            page_size = 250
            sign_ins = false
            service_principal_sign_ins = true
            directory_audits = true
            "#,
        )
        .unwrap();

        assert_eq!(config.poll_interval, Duration::from_secs(60));
        assert_eq!(config.lookback, Duration::from_secs(600));
        assert_eq!(config.max_window, Duration::from_secs(7200));
        assert_eq!(config.request_timeout, Duration::from_secs(15));
        assert_eq!(config.max_retry_after, Duration::from_secs(90));
        assert_eq!(config.rate_limit_retries, 1);
        assert_eq!(config.page_size, 250);
        assert_eq!(config.client_secret_env, None);
        assert!(
            !format!("{config:?}").contains("example-secret"),
            "the debug output must not show the secret"
        );

        let settings = config.validate(no_environment).unwrap();
        assert_eq!(settings.client_secret.expose_secret(), "example-secret");
        assert_eq!(
            settings.token_url.as_str(),
            "https://login.microsoftonline.us/contoso.example/oauth2/v2.0/token"
        );
        assert_eq!(settings.graph_base, "https://graph.microsoft.us");
        assert_eq!(settings.scope, "https://graph.microsoft.us/.default");
        assert_eq!(
            settings.feeds,
            [Feed::ServicePrincipalSignIns, Feed::DirectoryAudits]
        );
        assert_eq!(settings.max_retry_after, Duration::from_secs(90));
        assert_eq!(settings.rate_limit_retries, 1);
        assert_eq!(settings.page_size, 250);
    }

    #[test]
    fn a_toml_text_with_an_unknown_field_or_a_bad_duration_does_not_parse() {
        let base = r#"
            name = "entra-prod"
            tenant_id = "contoso.example"
            client_id = "11111111-1111-1111-1111-111111111111"
            client_secret = "example-secret"
        "#;
        toml::from_str::<EntraConfig>(base).unwrap();

        let error =
            toml::from_str::<EntraConfig>(&format!("{base}\nsecret = \"other\"")).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `secret`"),
            "{error}"
        );
        assert!(!error.to_string().contains("example-secret"), "{error}");

        let error = toml::from_str::<EntraConfig>(&format!("{base}\npoll_interval = \"soon\""))
            .unwrap_err();
        assert!(error.to_string().contains("poll_interval"), "{error}");

        let error =
            toml::from_str::<EntraConfig>(&format!("{base}\npoll_interval = 30")).unwrap_err();
        assert!(error.to_string().contains("poll_interval"), "{error}");

        let error = toml::from_str::<EntraConfig>("name = \"entra-prod\"").unwrap_err();
        assert!(
            error.to_string().contains("missing field `tenant_id`"),
            "{error}"
        );
    }

    #[test]
    fn debug_output_does_not_show_the_secret() {
        let config = config();
        let text = format!("{config:?}");
        assert!(text.contains("entra-test"), "{text}");
        assert!(!text.contains("example-secret"), "{text}");
        let settings = format!("{:?}", config.validate(no_environment).unwrap());
        assert!(!settings.contains("example-secret"), "{settings}");
    }

    #[test]
    fn a_base_url_must_use_https_except_for_a_loopback_address() {
        for base in [
            "http://127.0.0.1:8080",
            "http://localhost:1",
            "http://[::1]:9",
        ] {
            let mut config = config();
            config.login_base = base.to_owned();
            config.graph_base = base.to_owned();
            let settings = config.validate(no_environment).unwrap();
            assert_eq!(settings.graph_base, base);
        }
        for base in [
            "http://graph.example.com",
            "http://192.0.2.1",
            "ftp://graph.example.com",
            "graph.example.com",
            "https://user:password@graph.example.com",
            "https://graph.example.com/?a=b",
            "https://graph.example.com/#fragment",
        ] {
            let mut login = config();
            login.login_base = base.to_owned();
            assert!(config_error(&login).contains("login_base"), "{base}");
            let mut graph = config();
            graph.graph_base = base.to_owned();
            assert!(config_error(&graph).contains("graph_base"), "{base}");
        }
    }

    #[test]
    fn a_tenant_that_changes_the_token_path_is_a_configuration_error() {
        for tenant in ["", "a/b", "../common", "tenant?x=1", "ten ant", "a..b"] {
            let mut config = config();
            config.tenant_id = tenant.to_owned();
            assert!(config_error(&config).contains("tenant_id"), "{tenant:?}");
        }
        let mut domain = config();
        domain.tenant_id = "contoso.example".to_owned();
        let settings = domain.validate(no_environment).unwrap();
        assert_eq!(
            settings.token_url.as_str(),
            "https://login.microsoftonline.com/contoso.example/oauth2/v2.0/token"
        );
    }

    #[test]
    fn limits_that_stop_the_read_are_configuration_errors() {
        type Change = fn(&mut EntraConfig);
        let cases: [(&str, Change); 9] = [
            ("client_id is empty", |config| {
                config.client_id = " ".to_owned()
            }),
            ("poll_interval", |config| {
                config.poll_interval = Duration::ZERO
            }),
            ("request_timeout", |config| {
                config.request_timeout = Duration::ZERO
            }),
            ("whole numbers of seconds", |config| {
                config.lookback = Duration::from_millis(1500);
            }),
            ("whole numbers of seconds", |config| {
                config.max_window = Duration::from_millis(3_600_500);
            }),
            ("max_window must be more than lookback", |config| {
                config.max_window = config.lookback;
            }),
            ("page_size", |config| config.page_size = 0),
            ("page_size", |config| config.page_size = 1001),
            ("enable sign_ins", |config| {
                config.sign_ins = false;
                config.directory_audits = false;
            }),
        ];
        for (expected, change) in cases {
            let mut config = config();
            change(&mut config);
            let message = config_error(&config);
            assert!(message.contains(expected), "{expected}: {message}");
        }
        let mut name = config();
        name.name = "entra.prod".to_owned();
        assert!(config_error(&name).contains("connector name"));
    }
}
