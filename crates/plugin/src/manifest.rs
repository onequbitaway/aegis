//! The plugin manifest: the file that tells the host how to load and limit one plugin.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aegis_contracts::{Error, Result};
use serde::Deserialize;

use crate::http::HttpPolicy;

/// The longest plugin name, in characters.
const MAX_NAME_CHARS: usize = 64;
/// The poll interval of a manifest that gives none.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// The number of hexadecimal digits in a SHA-256 value.
const SHA256_HEX_DIGITS: usize = 64;

/// The contract that a plugin implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    /// The plugin is a source connector. It implements the `source-connector` world.
    Source,
    /// The plugin is an action connector. It implements the `action-connector` world.
    Action,
}

impl fmt::Display for PluginKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Source => "source",
            Self::Action => "action",
        })
    }
}

/// The data that the host needs to load one plugin.
///
/// The manifest is a TOML file next to the component file:
///
/// ```toml
/// name = "webhook-notify"
/// kind = "action"
/// component = "example_action.wasm"
/// sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
/// poll_interval_ms = 30000
/// allowed_hosts = ["hooks.example.com"]
///
/// [config]
/// webhook_url = "https://hooks.example.com/services/T000/B000"
/// ```
///
/// Only `name`, `kind`, and `component` are necessary. The operator writes the manifest.
/// A plugin cannot change it.
///
/// The `Debug` output shows the keys of `config` and hides the values, because a value
/// can be a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct PluginManifest {
    /// The name of the connector instance. The host uses it as the connector name.
    ///
    /// Use 1 to 64 characters from `a-z`, `A-Z`, `0-9`, `_`, and `-`.
    pub name: String,
    /// The contract that the plugin implements.
    pub kind: PluginKind,
    /// The path of the component file.
    ///
    /// In a manifest file, the path is relative to the directory of the manifest file.
    pub component: PathBuf,
    /// The SHA-256 of the component file, as 64 hexadecimal digits.
    ///
    /// When the value is present, the host loads the component only if the value matches.
    pub sha256: Option<String>,
    /// The time between two `poll` calls of a source plugin. The TOML key is
    /// `poll_interval_ms`. The default value is 30 seconds.
    pub poll_interval: Duration,
    /// The destinations that the plugin can send HTTP requests to.
    ///
    /// Each entry is `host` or `host:port`. The match is exact: no wildcards and no
    /// subdomains. An entry without a port permits only the default port of the scheme.
    /// With an empty list, the plugin has no network access.
    pub allowed_hosts: Vec<String>,
    /// The configuration that the plugin reads with `config-get`.
    pub config: BTreeMap<String, String>,
}

/// The TOML form of a manifest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    name: String,
    kind: PluginKind,
    component: PathBuf,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    poll_interval_ms: Option<u64>,
    #[serde(default)]
    allowed_hosts: Vec<String>,
    #[serde(default)]
    config: BTreeMap<String, toml::Value>,
}

impl PluginManifest {
    /// Makes a manifest with no hash, the default poll interval, no permitted hosts, and
    /// no configuration.
    pub fn new(name: impl Into<String>, kind: PluginKind, component: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            kind,
            component: component.into(),
            sha256: None,
            poll_interval: DEFAULT_POLL_INTERVAL,
            allowed_hosts: Vec::new(),
            config: BTreeMap::new(),
        }
    }

    /// Reads and checks a manifest file.
    ///
    /// The component path in the file is relative to the directory of the file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the file does not exist, and [`Error::Config`] if the
    /// content is not a valid manifest.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|error| read_error(path, error))?;
        let directory = path.parent().unwrap_or_else(|| Path::new(""));
        Self::from_toml_str(&text, directory).map_err(|error| in_file(path, error))
    }

    /// Parses and checks the TOML text of a manifest.
    ///
    /// `directory` is the directory that holds the component file. The component path in
    /// the text must be relative and must stay in that directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the text is not a valid manifest. The message does not
    /// contain a configuration value.
    pub fn from_toml_str(text: &str, directory: impl AsRef<Path>) -> Result<Self> {
        let raw: RawManifest = toml::from_str(text).map_err(|error| {
            // The full error shows the source line, which can hold a secret. The message
            // alone does not.
            Error::Config(format!(
                "the plugin manifest is not valid: {}",
                error.message()
            ))
        })?;

        let stays_inside = raw
            .component
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir));
        if !stays_inside || raw.component.as_os_str().is_empty() {
            return Err(Error::Config(format!(
                "plugin {}: the component path must be relative and must not contain `..`",
                raw.name
            )));
        }

        let mut config = BTreeMap::new();
        for (key, value) in raw.config {
            let toml::Value::String(value) = value else {
                return Err(Error::Config(format!(
                    "plugin {}: the config value {key} must be a string",
                    raw.name
                )));
            };
            config.insert(key, value);
        }

        let manifest = Self {
            name: raw.name,
            kind: raw.kind,
            component: directory.as_ref().join(raw.component),
            sha256: raw.sha256,
            poll_interval: raw
                .poll_interval_ms
                .map_or(DEFAULT_POLL_INTERVAL, Duration::from_millis),
            allowed_hosts: raw.allowed_hosts,
            config,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Checks the values of the manifest.
    ///
    /// The host does this check before it loads a plugin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for a name, a hash, a poll interval, or a permitted host
    /// that is not valid.
    pub fn validate(&self) -> Result<()> {
        let name_is_valid = !self.name.is_empty()
            && self.name.len() <= MAX_NAME_CHARS
            && self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
        if !name_is_valid {
            return Err(Error::Config(
                "a plugin name must have 1 to 64 characters from a-z, A-Z, 0-9, `_`, and `-`"
                    .to_owned(),
            ));
        }
        if let Some(sha256) = &self.sha256 {
            let is_hash = sha256.len() == SHA256_HEX_DIGITS
                && sha256.bytes().all(|byte| byte.is_ascii_hexdigit());
            if !is_hash {
                return Err(Error::Config(format!(
                    "plugin {}: sha256 must be 64 hexadecimal digits",
                    self.name
                )));
            }
        }
        if self.poll_interval.is_zero() {
            return Err(Error::Config(format!(
                "plugin {}: the poll interval must be larger than zero",
                self.name
            )));
        }
        HttpPolicy::parse(&self.allowed_hosts)
            .map_err(|reason| Error::Config(format!("plugin {}: {reason}", self.name)))?;
        Ok(())
    }
}

impl fmt::Debug for PluginManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let config: BTreeMap<&str, &str> = self
            .config
            .keys()
            .map(|key| (key.as_str(), "<hidden>"))
            .collect();
        formatter
            .debug_struct("PluginManifest")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("component", &self.component)
            .field("sha256", &self.sha256)
            .field("poll_interval", &self.poll_interval)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("config", &config)
            .finish()
    }
}

/// Maps a failed file read to a contract error that names the file.
pub(crate) fn read_error(path: &Path, error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        Error::NotFound(format!("the plugin file {} does not exist", path.display()))
    } else {
        Error::other(format!("read the plugin file {}", path.display()), error)
    }
}

/// Adds the name of the manifest file to a configuration error.
fn in_file(path: &Path, error: Error) -> Error {
    match error {
        Error::Config(message) => Error::Config(format!("{}: {message}", path.display())),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
        name = "webhook-notify"
        kind = "action"
        component = "example_action.wasm"
        sha256 = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
        poll_interval_ms = 250
        allowed_hosts = ["hooks.example.com", "127.0.0.1:8080"]

        [config]
        webhook_url = "https://hooks.example.com/services/secret-path"
    "#;

    fn config_error(text: &str) -> String {
        match PluginManifest::from_toml_str(text, "/plugins") {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, got {other:?}"),
        }
    }

    #[test]
    fn a_full_manifest_parses_to_its_values() {
        let manifest = PluginManifest::from_toml_str(FULL, "/plugins").unwrap();
        assert_eq!(manifest.name, "webhook-notify");
        assert_eq!(manifest.kind, PluginKind::Action);
        assert_eq!(
            manifest.component,
            Path::new("/plugins/example_action.wasm")
        );
        assert_eq!(
            manifest.sha256.as_deref(),
            Some("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08")
        );
        assert_eq!(manifest.poll_interval, Duration::from_millis(250));
        assert_eq!(
            manifest.allowed_hosts,
            ["hooks.example.com", "127.0.0.1:8080"]
        );
        assert_eq!(
            manifest.config.get("webhook_url").map(String::as_str),
            Some("https://hooks.example.com/services/secret-path")
        );
        assert_eq!(manifest.config.len(), 1);
    }

    #[test]
    fn a_minimal_manifest_gets_the_safe_defaults() {
        let text = "name = \"s\"\nkind = \"source\"\ncomponent = \"s.wasm\"\n";
        let manifest = PluginManifest::from_toml_str(text, "dir").unwrap();
        assert_eq!(
            manifest,
            PluginManifest::new("s", PluginKind::Source, "dir/s.wasm")
        );
        assert_eq!(manifest.sha256, None);
        assert_eq!(manifest.poll_interval, Duration::from_secs(30));
        assert!(manifest.allowed_hosts.is_empty());
        assert!(manifest.config.is_empty());
    }

    #[test]
    fn an_unknown_key_is_a_configuration_error() {
        let text = "name = \"s\"\nkind = \"source\"\ncomponent = \"s.wasm\"\nallowed_host = [\"a.example\"]\n";
        let message = config_error(text);
        assert!(message.contains("allowed_host"), "{message}");
    }

    #[test]
    fn a_missing_key_and_an_unknown_kind_are_configuration_errors() {
        let message = config_error("name = \"s\"\nkind = \"source\"\n");
        assert!(message.contains("component"), "{message}");
        let message = config_error("name = \"s\"\nkind = \"detector\"\ncomponent = \"s.wasm\"\n");
        assert!(message.contains("detector"), "{message}");
    }

    #[test]
    fn a_component_path_cannot_leave_the_plugin_directory() {
        for path in ["../other/s.wasm", "/etc/s.wasm", "a/../../s.wasm", ""] {
            let text = format!("name = \"s\"\nkind = \"source\"\ncomponent = \"{path}\"\n");
            let message = config_error(&text);
            assert_eq!(
                message, "plugin s: the component path must be relative and must not contain `..`",
                "{path}"
            );
        }
        let nested = "name = \"s\"\nkind = \"source\"\ncomponent = \"./bin/s.wasm\"\n";
        let manifest = PluginManifest::from_toml_str(nested, "/plugins").unwrap();
        assert_eq!(manifest.component, Path::new("/plugins/./bin/s.wasm"));
    }

    #[test]
    fn a_name_must_be_one_safe_subject_token() {
        for name in ["", "a.b", "a b", "a*", "a>", "é", &"a".repeat(65)] {
            let manifest = PluginManifest::new(name, PluginKind::Source, "s.wasm");
            let error = manifest.validate().unwrap_err();
            assert!(
                matches!(&error, Error::Config(message)
                    if message == "a plugin name must have 1 to 64 characters from a-z, A-Z, 0-9, `_`, and `-`"),
                "{name:?}: {error:?}"
            );
        }
        for name in ["a", "Entra_prod-2", &"a".repeat(64)] {
            PluginManifest::new(name, PluginKind::Source, "s.wasm")
                .validate()
                .unwrap();
        }
    }

    #[test]
    fn a_hash_must_be_64_hexadecimal_digits() {
        let mut manifest = PluginManifest::new("s", PluginKind::Source, "s.wasm");
        for hash in ["abc", &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            manifest.sha256 = Some(hash.to_owned());
            let error = manifest.validate().unwrap_err();
            assert!(
                matches!(&error, Error::Config(message)
                    if message == "plugin s: sha256 must be 64 hexadecimal digits"),
                "{hash:?}: {error:?}"
            );
        }
        manifest.sha256 = Some("aB".repeat(32));
        manifest.validate().unwrap();
    }

    #[test]
    fn a_zero_poll_interval_is_a_configuration_error() {
        let text =
            "name = \"s\"\nkind = \"source\"\ncomponent = \"s.wasm\"\npoll_interval_ms = 0\n";
        let message = config_error(text);
        assert_eq!(
            message,
            "plugin s: the poll interval must be larger than zero"
        );
    }

    #[test]
    fn a_permitted_host_that_is_not_valid_is_a_configuration_error() {
        let text = "name = \"s\"\nkind = \"source\"\ncomponent = \"s.wasm\"\nallowed_hosts = [\"*.example.com\"]\n";
        let message = config_error(text);
        assert!(message.contains("*.example.com"), "{message}");
    }

    #[test]
    fn errors_and_debug_output_do_not_show_configuration_values() {
        let not_a_string = "name = \"s\"\nkind = \"source\"\ncomponent = \"s.wasm\"\n[config]\napi_token = 123456789\n";
        let message = config_error(not_a_string);
        assert_eq!(
            message,
            "plugin s: the config value api_token must be a string"
        );

        let broken_line = "name = \"s\"\nkind = \"source\"\ncomponent = \"s.wasm\"\n[config]\napi_token = \"hunter2-secret\n";
        let message = config_error(broken_line);
        assert!(!message.contains("hunter2-secret"), "{message}");

        let manifest = PluginManifest::from_toml_str(FULL, "/plugins").unwrap();
        let debug = format!("{manifest:?}");
        assert!(debug.contains("webhook_url"), "{debug}");
        assert!(debug.contains("webhook-notify"), "{debug}");
        assert!(!debug.contains("secret-path"), "{debug}");
    }

    #[test]
    fn from_file_resolves_the_component_next_to_the_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.toml");
        std::fs::write(&path, FULL).unwrap();
        let manifest = PluginManifest::from_file(&path).unwrap();
        assert_eq!(
            manifest.component,
            directory.path().join("example_action.wasm")
        );
    }

    #[test]
    fn from_file_names_the_file_in_its_errors() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.toml");
        let error = PluginManifest::from_file(&missing).unwrap_err();
        assert!(
            matches!(&error, Error::NotFound(message) if message.contains("missing.toml")),
            "{error:?}"
        );

        let broken = directory.path().join("broken.toml");
        std::fs::write(&broken, "name = ").unwrap();
        let error = PluginManifest::from_file(&broken).unwrap_err();
        assert!(
            matches!(&error, Error::Config(message) if message.contains("broken.toml")),
            "{error:?}"
        );
    }
}
