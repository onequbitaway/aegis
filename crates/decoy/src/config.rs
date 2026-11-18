//! The configuration of a decoy service.
//!
//! [`DecoyConfig`] implements `serde::Deserialize`. An unknown key is an error. The
//! configuration holds the names of environment variables, never a secret.

use std::net::SocketAddr;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use serde::{Deserialize, Serialize};

/// The path below which the decoy model API answers.
pub const MODEL_API_ROOT: &str = "/v1";

/// The largest number of characters in the name of a decoy.
const MAX_NAME_LENGTH: usize = 64;
/// The smallest value of [`LimitsConfig::max_response_bytes`].
///
/// One generated page or one generated JSON answer always fits in this number of bytes.
pub(crate) const MIN_RESPONSE_BYTES: usize = 64 * 1024;
/// The largest number of bytes that one complete generated body can have.
pub(crate) const REPLY_BUFFER_BYTES: usize = 32 * 1024;
/// The largest number of bytes that the text of one request, without the prompt, adds to
/// the recorded data of one connection.
pub(crate) const CAPTURE_BYTES: usize = 32 * 1024;
/// The largest number of bytes that one recorded character can use.
pub(crate) const BYTES_PER_CHARACTER: usize = 4;
/// The longest interval and the longest delay of a persona.
const MAX_PACE: Duration = Duration::from_secs(60 * 60);

/// A persona of a decoy service.
///
/// A persona is one behavior that the decoy shows to a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonaKind {
    /// Answers each request with a valid response that arrives very slowly.
    Tarpit,
    /// Serves an endless set of generated pages and an endless JSON API.
    Maze,
    /// Serves an OpenAI-compatible API that accepts only planted decoy keys.
    ModelApi,
}

impl PersonaKind {
    /// Returns the value of the `decoy_kind` attribute for this persona.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tarpit => "tarpit",
            Self::Maze => "maze",
            Self::ModelApi => "model_api",
        }
    }
}

/// The configuration of one decoy service.
///
/// ```toml
/// id = "decoy-lab"
/// bind = "192.0.2.10:8081"
/// personas = ["tarpit", "maze", "model_api"]
/// seed_env = "AEGIS_DECOY_SEED"
///
/// [limits]
/// max_connections = 256
/// max_hold = "2m"
///
/// [[model_api.keys]]
/// id = "ht-decoy-model-key"
/// value_env = "AEGIS_DECOY_MODEL_KEY"
/// ```
///
/// The decoy does not examine the other listeners of the process. The caller must make
/// sure that `bind` is not the address of a different configured listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyConfig {
    /// The name of the decoy. It is the connector name and the `decoy_id` attribute.
    ///
    /// Use only ASCII letters, digits, `-`, and `_`, and not more than 64 characters.
    pub id: String,
    /// The address on which the decoy listens. Port 0 lets the operating system select.
    pub bind: SocketAddr,
    /// The personas that the decoy runs. The list must have one persona or more.
    pub personas: Vec<PersonaKind>,
    /// The name of the environment variable that holds the secret seed.
    ///
    /// The seed must have 32 characters or more. All generated content comes from it.
    pub seed_env: String,
    /// The hard limits of the service.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// The settings of the tarpit persona.
    #[serde(default)]
    pub tarpit: TarpitConfig,
    /// The settings of the maze persona.
    #[serde(default)]
    pub maze: MazeConfig,
    /// The settings of the model API persona.
    #[serde(default)]
    pub model_api: ModelApiConfig,
    /// The settings of the canary instruction.
    #[serde(default)]
    pub canary: CanaryConfig,
    /// The settings of the event queue.
    #[serde(default)]
    pub events: EventsConfig,
}

impl DecoyConfig {
    /// Makes a configuration with the default limits and the default persona settings.
    pub fn new(
        id: impl Into<String>,
        bind: SocketAddr,
        personas: impl IntoIterator<Item = PersonaKind>,
        seed_env: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            bind,
            personas: personas.into_iter().collect(),
            seed_env: seed_env.into(),
            limits: LimitsConfig::default(),
            tarpit: TarpitConfig::default(),
            maze: MazeConfig::default(),
            model_api: ModelApiConfig::default(),
            canary: CanaryConfig::default(),
            events: EventsConfig::default(),
        }
    }

    /// Returns `true` if the configuration turns on the persona `kind`.
    #[must_use]
    pub fn has_persona(&self, kind: PersonaKind) -> bool {
        self.personas.contains(&kind)
    }

    /// Checks all values of the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] with the name of the first value that is not valid. The
    /// message never shows a secret, because the configuration holds none.
    pub fn validate(&self) -> Result<()> {
        match self.problem() {
            None => Ok(()),
            Some(problem) => Err(Error::Config(format!("decoy configuration: {problem}"))),
        }
    }

    fn problem(&self) -> Option<String> {
        if let Some(problem) = name_problem(&self.id) {
            return Some(format!("id: {problem}"));
        }
        if !is_variable_name(&self.seed_env) {
            return Some("seed_env must be the name of an environment variable".to_owned());
        }
        if self.personas.is_empty() {
            return Some("personas must have one persona or more".to_owned());
        }
        for (index, kind) in self.personas.iter().enumerate() {
            if self
                .personas
                .iter()
                .skip(index + 1)
                .any(|next| next == kind)
            {
                return Some(format!("personas has {} two times", kind.as_str()));
            }
        }
        self.limits
            .problem()
            .or_else(|| self.tarpit.problem())
            .or_else(|| self.maze.problem())
            .or_else(|| self.model_api.problem())
            .or_else(|| self.canary.problem())
            .or_else(|| self.events.problem(&self.model_api))
            .or_else(|| self.path_overlap())
    }

    /// Returns a problem if two path prefixes of the decoy cover the same path.
    fn path_overlap(&self) -> Option<String> {
        let prefixes = [
            ("the model API root", MODEL_API_ROOT),
            ("maze.page_root", self.maze.page_root.as_str()),
            ("maze.api_root", self.maze.api_root.as_str()),
            ("canary.path_prefix", self.canary.path_prefix.as_str()),
        ];
        for (index, (first_name, first)) in prefixes.iter().enumerate() {
            for (second_name, second) in prefixes.iter().skip(index + 1) {
                if path_is_within(first, second) || path_is_within(second, first) {
                    return Some(format!(
                        "{first_name} and {second_name} must not cover the same path"
                    ));
                }
            }
        }
        None
    }
}

/// The hard limits of a decoy service.
///
/// The limits make sure that a client cannot use the decoy against the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// The largest number of connections at the same time. The default is 256.
    pub max_connections: usize,
    /// The largest number of connections of one client address. The default is 8.
    ///
    /// For IPv6, one address is one `/64` network.
    pub max_connections_per_address: usize,
    /// The largest size of the request line and the headers. The default is 8192 bytes.
    pub max_header_bytes: usize,
    /// The largest number of request headers. The default is 64.
    pub max_headers: usize,
    /// The largest size of a request body. The default is 65536 bytes.
    pub max_body_bytes: usize,
    /// The time in which the client must send the request line and all headers.
    ///
    /// The default is 10 seconds.
    #[serde(with = "humantime_serde")]
    pub header_read_timeout: Duration,
    /// The time in which the client must send the full request body.
    ///
    /// The default is 10 seconds.
    #[serde(with = "humantime_serde")]
    pub body_read_timeout: Duration,
    /// The longest time that one write to the client can take. The default is 10 seconds.
    #[serde(with = "humantime_serde")]
    pub write_timeout: Duration,
    /// The longest time that the decoy keeps one connection. The default is 2 minutes.
    ///
    /// The time starts when the decoy accepts the connection. At this limit, the decoy
    /// ends the answer. The last write gets one `write_timeout` more.
    #[serde(with = "humantime_serde")]
    pub max_hold: Duration,
    /// The largest number of bytes that the decoy sends on one connection.
    ///
    /// The default is 262144 bytes. The smallest value is 65536 bytes.
    pub max_response_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_connections_per_address: 8,
            max_header_bytes: 8 * 1024,
            max_headers: 64,
            max_body_bytes: 64 * 1024,
            header_read_timeout: Duration::from_secs(10),
            body_read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            max_hold: Duration::from_secs(120),
            max_response_bytes: 256 * 1024,
        }
    }
}

impl LimitsConfig {
    fn problem(&self) -> Option<String> {
        range_problem("limits.max_connections", self.max_connections, 1, 65_536)
            .or_else(|| {
                range_problem(
                    "limits.max_connections_per_address",
                    self.max_connections_per_address,
                    1,
                    self.max_connections,
                )
            })
            .or_else(|| {
                range_problem(
                    "limits.max_header_bytes",
                    self.max_header_bytes,
                    256,
                    64 * 1024,
                )
            })
            .or_else(|| range_problem("limits.max_headers", self.max_headers, 1, 128))
            .or_else(|| range_problem("limits.max_body_bytes", self.max_body_bytes, 0, 1024 * 1024))
            .or_else(|| {
                range_problem(
                    "limits.max_response_bytes",
                    self.max_response_bytes,
                    MIN_RESPONSE_BYTES,
                    64 * 1024 * 1024,
                )
            })
            .or_else(|| {
                duration_problem(
                    "limits.header_read_timeout",
                    self.header_read_timeout,
                    Duration::from_millis(1),
                    Duration::from_secs(300),
                )
            })
            .or_else(|| {
                duration_problem(
                    "limits.body_read_timeout",
                    self.body_read_timeout,
                    Duration::from_millis(1),
                    Duration::from_secs(300),
                )
            })
            .or_else(|| {
                duration_problem(
                    "limits.write_timeout",
                    self.write_timeout,
                    Duration::from_millis(1),
                    Duration::from_secs(300),
                )
            })
            .or_else(|| {
                duration_problem(
                    "limits.max_hold",
                    self.max_hold,
                    Duration::from_millis(1),
                    Duration::from_secs(24 * 60 * 60),
                )
            })
    }
}

/// The settings of the tarpit persona.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TarpitConfig {
    /// The number of body bytes that the tarpit sends at each interval. The default is 8.
    pub chunk_bytes: usize,
    /// The time between two sends. The default is 1 second.
    ///
    /// The hold limit of the connection also ends a wait.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            chunk_bytes: 8,
            interval: Duration::from_secs(1),
        }
    }
}

impl TarpitConfig {
    fn problem(&self) -> Option<String> {
        range_problem("tarpit.chunk_bytes", self.chunk_bytes, 1, 1024).or_else(|| {
            duration_problem(
                "tarpit.interval",
                self.interval,
                Duration::from_millis(1),
                MAX_PACE,
            )
        })
    }
}

/// The settings of the maze persona.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MazeConfig {
    /// The path below which the maze serves generated pages. The default is `/docs`.
    pub page_root: String,
    /// The path below which the maze serves the JSON API. The default is `/api`.
    pub api_root: String,
    /// The number of links to other pages on each page. The default is 8.
    pub links_per_page: usize,
    /// The number of records in each answer of the JSON API. The default is 10.
    pub items_per_page: usize,
    /// The wait before the maze sends an answer. The default is 500 milliseconds.
    ///
    /// The hold limit of the connection also ends the wait.
    #[serde(with = "humantime_serde")]
    pub delay: Duration,
}

impl Default for MazeConfig {
    fn default() -> Self {
        Self {
            page_root: "/docs".to_owned(),
            api_root: "/api".to_owned(),
            links_per_page: 8,
            items_per_page: 10,
            delay: Duration::from_millis(500),
        }
    }
}

impl MazeConfig {
    fn problem(&self) -> Option<String> {
        prefix_problem("maze.page_root", &self.page_root)
            .or_else(|| prefix_problem("maze.api_root", &self.api_root))
            .or_else(|| range_problem("maze.links_per_page", self.links_per_page, 1, 32))
            .or_else(|| range_problem("maze.items_per_page", self.items_per_page, 1, 50))
            .or_else(|| duration_problem("maze.delay", self.delay, Duration::ZERO, MAX_PACE))
    }
}

/// One decoy API key that the operator planted.
///
/// The key is a honeytoken. It gives no access to any system. Plant it only in a place
/// that no legitimate process reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyKeyConfig {
    /// The identifier of the honeytoken. Events show this identifier, never the key.
    pub id: String,
    /// The name of the environment variable that holds the decoy key.
    ///
    /// The key must have 16 to 512 visible ASCII characters.
    pub value_env: String,
}

impl DecoyKeyConfig {
    /// Makes the configuration of one decoy key.
    pub fn new(id: impl Into<String>, value_env: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            value_env: value_env.into(),
        }
    }
}

/// The settings of the model API persona.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelApiConfig {
    /// The decoy keys that the API accepts. Each other key gets the status 401.
    pub keys: Vec<DecoyKeyConfig>,
    /// The model names that `GET /v1/models` lists.
    pub models: Vec<String>,
    /// The time between two parts of an answer. The default is 750 milliseconds.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// The number of words in one filler answer. The default is 160.
    pub answer_words: usize,
    /// The largest number of prompt characters that the decoy records.
    ///
    /// The default is 4000.
    pub max_prompt_chars: usize,
}

impl Default for ModelApiConfig {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            models: vec!["assistant-large".to_owned(), "assistant-small".to_owned()],
            interval: Duration::from_millis(750),
            answer_words: 160,
            max_prompt_chars: 4000,
        }
    }
}

impl ModelApiConfig {
    fn problem(&self) -> Option<String> {
        if self.keys.len() > 64 {
            return Some("model_api.keys must have 64 keys or fewer".to_owned());
        }
        for (index, key) in self.keys.iter().enumerate() {
            let length = key.id.chars().count();
            let valid = (1..=128).contains(&length)
                && key.id.trim() == key.id
                && !key.id.chars().any(char::is_control);
            if !valid {
                return Some(format!(
                    "model_api.keys[{index}].id must have 1 to 128 characters, no control characters, and no space at the ends"
                ));
            }
            if !is_variable_name(&key.value_env) {
                return Some(format!(
                    "model_api.keys[{index}].value_env must be the name of an environment variable"
                ));
            }
            let later = self.keys.iter().skip(index + 1);
            if later.clone().any(|next| next.id == key.id) {
                return Some(format!("model_api.keys has the id {} two times", key.id));
            }
            if later.clone().any(|next| next.value_env == key.value_env) {
                return Some(format!(
                    "model_api.keys has the variable {} two times",
                    key.value_env
                ));
            }
        }
        if let Some(problem) = range_problem("model_api.models", self.models.len(), 1, 16) {
            return Some(problem);
        }
        if !self.models.iter().all(|model| is_model_name(model)) {
            return Some(
                "model_api.models: a name must have 1 to 64 ASCII letters, digits, '.', '_', ':', or '-'"
                    .to_owned(),
            );
        }
        duration_problem(
            "model_api.interval",
            self.interval,
            Duration::from_millis(1),
            MAX_PACE,
        )
        .or_else(|| range_problem("model_api.answer_words", self.answer_words, 1, 1000))
        .or_else(|| {
            range_problem(
                "model_api.max_prompt_chars",
                self.max_prompt_chars,
                0,
                32_768,
            )
        })
    }
}

/// The settings of the canary instruction.
///
/// The instruction asks an automated agent to fetch one URL on this decoy. It asks for
/// nothing else. The text of the instruction is fixed and has no setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CanaryConfig {
    /// With `true`, the answers of the decoy carry the instruction. The default is `true`.
    pub enabled: bool,
    /// The path below which the canary URLs are. The default is `/ref`.
    pub path_prefix: String,
    /// The origin of the decoy as a client sees it, for example `http://192.0.2.10:8081`.
    ///
    /// With no origin, the instruction holds only the path of the canary URL. The decoy
    /// never takes the origin from a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path_prefix: "/ref".to_owned(),
            origin: None,
        }
    }
}

impl CanaryConfig {
    fn problem(&self) -> Option<String> {
        if let Some(problem) = prefix_problem("canary.path_prefix", &self.path_prefix) {
            return Some(problem);
        }
        match self.origin.as_deref() {
            Some(origin) if !is_origin(origin) => Some(
                "canary.origin must be http:// or https://, then a host, then an optional port, and nothing more"
                    .to_owned(),
            ),
            _ => None,
        }
    }
}

/// The settings of the event queue.
///
/// The queue holds the events until the ingestion runner reads them. When the queue is
/// full, the decoy counts each new event as dropped and reports the count in an event.
///
/// A canary hit and a honeytoken trip can use all of the queue. A contact with a request
/// can use three quarters of it. A contact with no request can use half of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventsConfig {
    /// The largest number of events in the queue. The default is 4096.
    pub max_queued: usize,
    /// The largest size of all events in the queue, as JSON. The default is 8 MiB.
    pub max_queued_bytes: usize,
    /// The largest number of events in one batch. The default is 100.
    pub batch_size: usize,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            max_queued: 4096,
            max_queued_bytes: 8 * 1024 * 1024,
            batch_size: 100,
        }
    }
}

impl EventsConfig {
    /// Returns the smallest queue size that can hold one event with a full prompt.
    fn smallest_queue_bytes(model_api: &ModelApiConfig) -> usize {
        CAPTURE_BYTES + BYTES_PER_CHARACTER * model_api.max_prompt_chars
    }

    fn problem(&self, model_api: &ModelApiConfig) -> Option<String> {
        range_problem("events.max_queued", self.max_queued, 1, 1_000_000)
            .or_else(|| {
                range_problem(
                    "events.max_queued_bytes",
                    self.max_queued_bytes,
                    Self::smallest_queue_bytes(model_api),
                    1024 * 1024 * 1024,
                )
            })
            .or_else(|| range_problem("events.batch_size", self.batch_size, 1, 1000))
    }
}

/// Returns `true` if `path` is `prefix` or is below `prefix`.
pub(crate) fn path_is_within(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Returns the reason why `name` is not a valid decoy name, if it is not valid.
///
/// The name becomes one token of a bus subject. Thus only ASCII letters, digits, `-`, and
/// `_` are permitted. The ingestion runner has the same rule.
fn name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("the name is empty".to_owned());
    }
    if name.len() > MAX_NAME_LENGTH {
        return Some(format!(
            "the name is longer than {MAX_NAME_LENGTH} characters"
        ));
    }
    let permitted =
        |character: char| character.is_ascii_alphanumeric() || character == '-' || character == '_';
    if name.chars().all(permitted) {
        None
    } else {
        Some("the name has a character that is not a letter, a digit, '-', or '_'".to_owned())
    }
}

/// Returns `true` if `name` can be the name of an environment variable.
fn is_variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    let first_is_valid = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
    first_is_valid
        && name.len() <= 128
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Returns `true` if `name` is a model name that the decoy can show in an answer.
pub(crate) fn is_model_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
}

/// Returns the reason why `prefix` is not a valid path prefix, if it is not valid.
fn prefix_problem(name: &str, prefix: &str) -> Option<String> {
    let Some(rest) = prefix.strip_prefix('/') else {
        return Some(format!("{name} must start with '/'"));
    };
    if !(2..=64).contains(&prefix.len()) {
        return Some(format!("{name} must have 2 to 64 characters"));
    }
    let segments_are_valid = rest.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '~' | '-')
            })
    });
    if segments_are_valid {
        None
    } else {
        Some(format!(
            "{name} must have segments of ASCII letters, digits, '.', '_', '~', or '-', and no '/' at the end"
        ))
    }
}

/// Returns `true` if `origin` is a scheme, a host, and an optional port, and nothing more.
fn is_origin(origin: &str) -> bool {
    let Some(authority) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    if authority.is_empty() || authority.len() > 255 {
        return false;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // An IPv6 address in brackets.
        let Some((address, after)) = rest.split_once(']') else {
            return false;
        };
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        match after.strip_prefix(':') {
            Some(port) => (None, Some(port)),
            None if after.is_empty() => (None, None),
            None => return false,
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (Some(host), Some(port)),
            None => (Some(authority), None),
        }
    };
    let host_is_valid = host.is_none_or(|host| {
        !host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '-')
            })
    });
    let port_is_valid = port.is_none_or(|port| {
        !port.is_empty()
            && port.len() <= 5
            && port.chars().all(|character| character.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|number| number != 0)
    });
    host_is_valid && port_is_valid
}

fn range_problem(name: &str, value: usize, min: usize, max: usize) -> Option<String> {
    if (min..=max).contains(&value) {
        None
    } else {
        Some(format!("{name} must be from {min} to {max}"))
    }
}

fn duration_problem(name: &str, value: Duration, min: Duration, max: Duration) -> Option<String> {
    if (min..=max).contains(&value) {
        None
    } else {
        Some(format!(
            "{name} must be from {} ms to {} ms",
            min.as_millis(),
            max.as_millis()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DecoyConfig {
        DecoyConfig::new(
            "decoy-test",
            SocketAddr::from(([127, 0, 0, 1], 0)),
            [
                PersonaKind::Tarpit,
                PersonaKind::Maze,
                PersonaKind::ModelApi,
            ],
            "AEGIS_DECOY_SEED",
        )
    }

    fn problem_of(change: impl FnOnce(&mut DecoyConfig)) -> String {
        let mut changed = config();
        change(&mut changed);
        match changed.validate() {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, got {other:?}"),
        }
    }

    #[test]
    fn the_default_configuration_is_valid() {
        assert!(config().validate().is_ok());
    }

    #[test]
    fn a_pace_that_is_longer_than_the_hold_limit_is_valid() {
        // The hold limit ends each wait, so a short hold needs no other change.
        let mut config = config();
        config.limits.max_hold = Duration::from_millis(200);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_name_that_changes_the_bus_subject_is_not_valid() {
        let too_long = "x".repeat(MAX_NAME_LENGTH + 1);
        for name in ["", "a.b", "a b", "*", ">", "../x", "é", too_long.as_str()] {
            let message = problem_of(|config| config.id = name.to_owned());
            assert!(
                message.starts_with("decoy configuration: id: "),
                "{name:?}: {message}"
            );
        }
        assert_eq!(name_problem(&"x".repeat(MAX_NAME_LENGTH)), None);
    }

    #[test]
    fn the_seed_variable_must_be_a_variable_name() {
        for name in ["", "1SEED", "A-B", "A B", "A=B"] {
            assert_eq!(
                problem_of(|config| config.seed_env = name.to_owned()),
                "decoy configuration: seed_env must be the name of an environment variable",
                "{name:?}"
            );
        }
    }

    #[test]
    fn the_persona_list_must_have_each_persona_one_time_at_most() {
        assert_eq!(
            problem_of(|config| config.personas.clear()),
            "decoy configuration: personas must have one persona or more"
        );
        assert_eq!(
            problem_of(|config| config.personas.push(PersonaKind::Maze)),
            "decoy configuration: personas has maze two times"
        );
    }

    #[test]
    fn each_limit_has_a_range() {
        assert_eq!(
            problem_of(|config| config.limits.max_connections = 0),
            "decoy configuration: limits.max_connections must be from 1 to 65536"
        );
        assert_eq!(
            problem_of(|config| config.limits.max_connections_per_address = 257),
            "decoy configuration: limits.max_connections_per_address must be from 1 to 256"
        );
        assert_eq!(
            problem_of(|config| config.limits.max_header_bytes = 255),
            "decoy configuration: limits.max_header_bytes must be from 256 to 65536"
        );
        assert_eq!(
            problem_of(|config| config.limits.max_headers = 129),
            "decoy configuration: limits.max_headers must be from 1 to 128"
        );
        assert_eq!(
            problem_of(|config| config.limits.max_body_bytes = 1024 * 1024 + 1),
            "decoy configuration: limits.max_body_bytes must be from 0 to 1048576"
        );
        assert_eq!(
            problem_of(|config| config.limits.max_response_bytes = MIN_RESPONSE_BYTES - 1),
            "decoy configuration: limits.max_response_bytes must be from 65536 to 67108864"
        );
        assert_eq!(
            problem_of(|config| config.limits.max_hold = Duration::ZERO),
            "decoy configuration: limits.max_hold must be from 1 ms to 86400000 ms"
        );
        assert_eq!(
            problem_of(|config| config.limits.header_read_timeout = Duration::ZERO),
            "decoy configuration: limits.header_read_timeout must be from 1 ms to 300000 ms"
        );
        assert_eq!(
            problem_of(|config| config.limits.body_read_timeout = Duration::from_secs(301)),
            "decoy configuration: limits.body_read_timeout must be from 1 ms to 300000 ms"
        );
        assert_eq!(
            problem_of(|config| config.limits.write_timeout = Duration::ZERO),
            "decoy configuration: limits.write_timeout must be from 1 ms to 300000 ms"
        );
    }

    #[test]
    fn the_persona_settings_have_ranges() {
        assert_eq!(
            problem_of(|config| config.tarpit.chunk_bytes = 0),
            "decoy configuration: tarpit.chunk_bytes must be from 1 to 1024"
        );
        assert_eq!(
            problem_of(|config| config.tarpit.interval = Duration::from_secs(3601)),
            "decoy configuration: tarpit.interval must be from 1 ms to 3600000 ms"
        );
        assert_eq!(
            problem_of(|config| config.maze.links_per_page = 33),
            "decoy configuration: maze.links_per_page must be from 1 to 32"
        );
        assert_eq!(
            problem_of(|config| config.maze.items_per_page = 0),
            "decoy configuration: maze.items_per_page must be from 1 to 50"
        );
        assert_eq!(
            problem_of(|config| config.maze.delay = Duration::from_secs(3601)),
            "decoy configuration: maze.delay must be from 0 ms to 3600000 ms"
        );
        assert_eq!(
            problem_of(|config| config.model_api.answer_words = 1001),
            "decoy configuration: model_api.answer_words must be from 1 to 1000"
        );
        assert_eq!(
            problem_of(|config| config.model_api.max_prompt_chars = 32_769),
            "decoy configuration: model_api.max_prompt_chars must be from 0 to 32768"
        );
        assert_eq!(
            problem_of(|config| config.model_api.interval = Duration::ZERO),
            "decoy configuration: model_api.interval must be from 1 ms to 3600000 ms"
        );
        assert_eq!(
            problem_of(|config| config.model_api.models.clear()),
            "decoy configuration: model_api.models must be from 1 to 16"
        );
        assert!(
            problem_of(|config| config.model_api.models = vec!["a b".to_owned()])
                .starts_with("decoy configuration: model_api.models: a name must have")
        );
    }

    #[test]
    fn a_decoy_key_needs_a_clean_id_and_a_variable_name() {
        let key = |id: &str, variable: &str| DecoyKeyConfig::new(id, variable);
        assert!(
            problem_of(|config| config.model_api.keys = vec![key("", "KEY_A")])
                .starts_with("decoy configuration: model_api.keys[0].id must have 1 to 128")
        );
        assert!(
            problem_of(|config| config.model_api.keys = vec![key("ht\n1", "KEY_A")])
                .starts_with("decoy configuration: model_api.keys[0].id must have 1 to 128")
        );
        assert_eq!(
            problem_of(|config| config.model_api.keys = vec![key("ht-1", "KEY-A")]),
            "decoy configuration: model_api.keys[0].value_env must be the name of an environment variable"
        );
        assert_eq!(
            problem_of(|config| {
                config.model_api.keys = vec![key("ht-1", "KEY_A"), key("ht-1", "KEY_B")];
            }),
            "decoy configuration: model_api.keys has the id ht-1 two times"
        );
        assert_eq!(
            problem_of(|config| {
                config.model_api.keys = vec![key("ht-1", "KEY_A"), key("ht-2", "KEY_A")];
            }),
            "decoy configuration: model_api.keys has the variable KEY_A two times"
        );
    }

    #[test]
    fn a_path_prefix_must_be_a_clean_absolute_path() {
        for prefix in [
            "", "docs", "/", "/docs/", "/a//b", "/a/../b", "/a/.", "/a b", "/a?b", "/é",
        ] {
            assert!(
                problem_of(|config| config.maze.page_root = prefix.to_owned())
                    .starts_with("decoy configuration: maze.page_root must "),
                "{prefix:?}"
            );
        }
        assert_eq!(prefix_problem("x", "/kb/v2.1/pages_a~b-c"), None);
        assert_eq!(
            problem_of(|config| config.canary.path_prefix = format!("/{}", "a".repeat(64))),
            "decoy configuration: canary.path_prefix must have 2 to 64 characters"
        );
    }

    #[test]
    fn two_prefixes_must_not_cover_the_same_path() {
        assert_eq!(
            problem_of(|config| config.maze.page_root = "/api".to_owned()),
            "decoy configuration: maze.page_root and maze.api_root must not cover the same path"
        );
        assert_eq!(
            problem_of(|config| config.maze.api_root = "/docs/api".to_owned()),
            "decoy configuration: maze.page_root and maze.api_root must not cover the same path"
        );
        assert_eq!(
            problem_of(|config| config.maze.api_root = "/v1/data".to_owned()),
            "decoy configuration: the model API root and maze.api_root must not cover the same path"
        );
        assert_eq!(
            problem_of(|config| config.canary.path_prefix = "/docs".to_owned()),
            "decoy configuration: maze.page_root and canary.path_prefix must not cover the same path"
        );
        // A prefix that only starts with the same letters is a different path.
        let mut config = config();
        config.maze.api_root = "/docs-api".to_owned();
        config.canary.path_prefix = "/v10".to_owned();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn the_canary_origin_is_a_scheme_a_host_and_an_optional_port() {
        for origin in [
            "http://decoy.example",
            "https://decoy.example:8443",
            "http://192.0.2.10:8081",
            "http://[2001:db8::10]",
            "http://[2001:db8::10]:8081",
        ] {
            assert!(is_origin(origin), "{origin}");
        }
        for origin in [
            "",
            "decoy.example",
            "ftp://decoy.example",
            "http://",
            "http://decoy.example/",
            "http://decoy.example/path",
            "http://user@decoy.example",
            "http://decoy.example:0",
            "http://decoy.example:99999",
            "http://decoy.example:80a",
            "http://decoy.example?x=1",
            "http://decoy.example#x",
            "http://-decoy.example",
            "http://decoy..example",
            "http://[2001:db8::10",
            "http://[not-an-address]",
            "http://[2001:db8::10]x",
            "http://dec oy.example",
            "http://decoy.example\r\nX: y",
        ] {
            assert!(!is_origin(origin), "{origin:?}");
        }
        assert!(
            problem_of(|config| config.canary.origin = Some("http://a/b".to_owned()))
                .starts_with("decoy configuration: canary.origin must be http:// or https://")
        );
    }

    #[test]
    fn the_queue_must_have_space_for_one_event_with_a_full_prompt() {
        let smallest = CAPTURE_BYTES + BYTES_PER_CHARACTER * 4000;
        assert_eq!(
            problem_of(|config| config.events.max_queued_bytes = smallest - 1),
            format!(
                "decoy configuration: events.max_queued_bytes must be from {smallest} to 1073741824"
            )
        );
        let mut config = config();
        config.events.max_queued_bytes = smallest;
        assert!(config.validate().is_ok());
        assert_eq!(
            problem_of(|config| config.events.max_queued = 0),
            "decoy configuration: events.max_queued must be from 1 to 1000000"
        );
        assert_eq!(
            problem_of(|config| config.events.batch_size = 1001),
            "decoy configuration: events.batch_size must be from 1 to 1000"
        );
    }

    #[test]
    fn a_path_is_within_a_prefix_only_at_a_segment_border() {
        assert!(path_is_within("/docs", "/docs"));
        assert!(path_is_within("/docs/a/b", "/docs"));
        assert!(!path_is_within("/docs-old", "/docs"));
        assert!(!path_is_within("/doc", "/docs"));
        assert!(!path_is_within("/", "/docs"));
    }

    #[test]
    fn the_persona_names_are_the_decoy_kind_values() {
        assert_eq!(PersonaKind::Tarpit.as_str(), "tarpit");
        assert_eq!(PersonaKind::Maze.as_str(), "maze");
        assert_eq!(PersonaKind::ModelApi.as_str(), "model_api");
        assert_eq!(
            serde_json::to_string(&PersonaKind::ModelApi).unwrap(),
            "\"model_api\""
        );
    }
}
