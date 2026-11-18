//! The Rego policy engine.
//!
//! [`RegoPolicyEngine`] evaluates the policy of the operator in the process. It uses no
//! sidecar and no network.
//!
//! # The decision rule
//!
//! The engine gives the [`PolicyInput`] to the policy as the `input` document. Then it reads
//! one rule. The default rule is [`DEFAULT_DECISION_RULE`]. The rule must return an object:
//!
//! | Field | Value |
//! | --- | --- |
//! | `effect` | `"allow"`, `"require_approval"`, or `"deny"`. Mandatory. |
//! | `tier` | `"auto"` or `"gated"`. Optional. The default is `input.default_tier`. |
//! | `reasons` | A list or a set of strings. Optional. The default is an empty list. |
//!
//! The engine has no rules of its own about targets or actions. It enforces what the policy
//! says.
//!
//! # What a policy can use
//!
//! A policy can use the Rego built-in functions for strings, numbers, sets, objects, regular
//! expressions, glob patterns, time, and network address ranges. A policy cannot open a
//! network connection and cannot read the environment of the process: the functions
//! `http.send`, `net.lookup_ip_addr`, and `opa.runtime` do not exist in this engine. A
//! policy that calls them gives no valid decision.
//!
//! The output of a `print` call in a policy goes to the log at the debug level. Use it to
//! examine a policy. Do not print secrets.
//!
//! # Fail closed
//!
//! The engine never permits an action when the policy gives no valid decision. In each of
//! these conditions, [`RegoPolicyEngine::decide`] returns a decision with
//! [`PolicyEffect::Deny`]:
//!
//! - The rule is undefined for the request.
//! - The evaluation fails. A built-in function error is an evaluation failure.
//! - The evaluation takes more time than the limit.
//! - The result is not an object, or it has no `effect`, an unknown `effect`, an unknown
//!   `tier`, a `reasons` value that is not a list of strings, or an unknown field.
//! - The request cannot be encoded as the `input` document.
//!
//! Such a decision has [`FAIL_CLOSED_POLICY`] in its `policy` field and
//! [`ActionTier::Gated`] as its tier. Its first reason tells the cause. A decision that the
//! policy made has the name of the rule in its `policy` field.
//!
//! The engine does not use an error for these conditions. [`PolicyEngine::evaluate`] always
//! returns a decision, so a caller has one fail-closed result to handle.

use std::fmt;
use std::fs;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use aegis_contracts::policy::{
    ActionTier, PolicyDecision, PolicyEffect, PolicyEngine, PolicyInput,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use regorus::utils::limits::ExecutionTimerConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error as ThisError;

/// The rule that the engine reads when the operator sets no rule.
pub const DEFAULT_DECISION_RULE: &str = "data.aegis.response.decision";

/// The `policy` field of a decision that the engine made because the policy gave no valid
/// decision.
pub const FAIL_CLOSED_POLICY: &str = "aegis.policy.fail_closed";

/// The evaluation time limit when the operator sets no limit.
pub const DEFAULT_EVALUATION_TIME_LIMIT: Duration =
    Duration::from_millis(DEFAULT_EVALUATION_TIME_LIMIT_MS);

/// [`DEFAULT_EVALUATION_TIME_LIMIT`] in milliseconds.
const DEFAULT_EVALUATION_TIME_LIMIT_MS: u64 = 1000;

/// The number of evaluation steps between two checks of the time limit.
const TIMER_CHECK_INTERVAL: NonZeroU32 = match NonZeroU32::new(64) {
    Some(interval) => interval,
    None => NonZeroU32::MIN,
};

/// The largest number of characters of policy text or of an error that a message shows.
const MESSAGE_LIMIT: usize = 400;

/// The largest number of characters of a policy value that a reason shows.
const VALUE_LIMIT: usize = 64;

/// The format of a data document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataFormat {
    /// JSON.
    Json,
    /// YAML.
    Yaml,
}

#[derive(Clone, PartialEq, Eq)]
enum Source {
    PolicyText {
        name: String,
        text: String,
    },
    PolicyFile(PathBuf),
    PolicyDirectory(PathBuf),
    DataText {
        name: String,
        format: DataFormat,
        text: String,
    },
    DataFile(PathBuf),
}

impl fmt::Debug for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyText { name, .. } => write!(formatter, "PolicyText({name})"),
            Self::PolicyFile(path) => write!(formatter, "PolicyFile({})", path.display()),
            Self::PolicyDirectory(path) => {
                write!(formatter, "PolicyDirectory({})", path.display())
            }
            Self::DataText { name, format, .. } => {
                write!(formatter, "DataText({name}, {format:?})")
            }
            Self::DataFile(path) => write!(formatter, "DataFile({})", path.display()),
        }
    }
}

/// The policy files and the data documents that an engine loads.
///
/// The engine loads the sources in the order in which you add them. The engine reads a
/// file each time it loads the sources, so [`RegoPolicyEngine::reload`] gets the present
/// contents of each file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySources {
    sources: Vec<Source>,
}

impl PolicySources {
    /// Makes an empty set of sources.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds Rego policy text. Error messages use `name` as the file name.
    #[must_use]
    pub fn policy_text(mut self, name: impl Into<String>, rego: impl Into<String>) -> Self {
        self.sources.push(Source::PolicyText {
            name: name.into(),
            text: rego.into(),
        });
        self
    }

    /// Adds one Rego policy file.
    #[must_use]
    pub fn policy_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.sources.push(Source::PolicyFile(path.into()));
        self
    }

    /// Adds each `*.rego` file in a directory, in file name order.
    ///
    /// The engine does not read subdirectories. A directory with no `*.rego` file is an
    /// error.
    #[must_use]
    pub fn policy_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.sources.push(Source::PolicyDirectory(path.into()));
        self
    }

    /// Adds a data document as text. The top level must be an object.
    ///
    /// The engine merges the document into the Rego `data` document.
    #[must_use]
    pub fn data_text(
        mut self,
        name: impl Into<String>,
        format: DataFormat,
        text: impl Into<String>,
    ) -> Self {
        self.sources.push(Source::DataText {
            name: name.into(),
            format,
            text: text.into(),
        });
        self
    }

    /// Adds one data file. The extension must be `.json`, `.yaml`, or `.yml`.
    #[must_use]
    pub fn data_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.sources.push(Source::DataFile(path.into()));
        self
    }
}

/// The settings of a [`RegoPolicyEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineOptions {
    /// The rule that gives the decision. It must start with `data.`.
    pub rule: String,
    /// The longest permitted time for one evaluation. With `None`, there is no limit.
    pub evaluation_time_limit: Option<Duration>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            rule: DEFAULT_DECISION_RULE.to_owned(),
            evaluation_time_limit: Some(DEFAULT_EVALUATION_TIME_LIMIT),
        }
    }
}

impl EngineOptions {
    /// Sets the rule that gives the decision.
    #[must_use]
    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.rule = rule.into();
        self
    }

    /// Sets the longest permitted time for one evaluation.
    #[must_use]
    pub fn with_evaluation_time_limit(mut self, limit: Option<Duration>) -> Self {
        self.evaluation_time_limit = limit;
        self
    }
}

/// The configuration of a [`RegoPolicyEngine`].
///
/// Each subsystem reads its own table of the AEGIS configuration file. This type is the
/// table of the policy engine. A relative path starts at the working directory of the
/// process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// The policy files and the policy directories. One or more paths are necessary.
    ///
    /// From a directory, the engine loads each `*.rego` file in file name order. It does
    /// not read subdirectories.
    pub paths: Vec<PathBuf>,
    /// The data files. The extension of each file must be `.json`, `.yaml`, or `.yml`.
    #[serde(default)]
    pub data: Vec<PathBuf>,
    /// The rule that gives the decision. The default is [`DEFAULT_DECISION_RULE`].
    #[serde(default = "default_rule")]
    pub rule: String,
    /// The longest permitted time for one evaluation, in milliseconds.
    ///
    /// The value must be larger than 0. The default is 1000.
    #[serde(default = "default_time_limit_ms")]
    pub evaluation_time_limit_ms: u64,
}

fn default_rule() -> String {
    DEFAULT_DECISION_RULE.to_owned()
}

const fn default_time_limit_ms() -> u64 {
    DEFAULT_EVALUATION_TIME_LIMIT_MS
}

impl PolicyConfig {
    /// Makes a configuration with `paths` and the default values of the other fields.
    pub fn new(paths: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        Self {
            paths: paths.into_iter().map(Into::into).collect(),
            data: Vec::new(),
            rule: default_rule(),
            evaluation_time_limit_ms: default_time_limit_ms(),
        }
    }

    /// Returns the sources that the configuration names.
    ///
    /// A path that is a directory at the time of this call becomes a policy directory.
    /// Each other path becomes a policy file.
    #[must_use]
    pub fn sources(&self) -> PolicySources {
        let mut sources = PolicySources::new();
        for path in &self.paths {
            sources = if path.is_dir() {
                sources.policy_directory(path)
            } else {
                sources.policy_file(path)
            };
        }
        for path in &self.data {
            sources = sources.data_file(path);
        }
        sources
    }

    /// Returns the engine settings that the configuration gives.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `evaluation_time_limit_ms` is 0.
    pub fn options(&self) -> Result<EngineOptions> {
        if self.evaluation_time_limit_ms == 0 {
            return Err(Error::Config(
                "the policy setting evaluation_time_limit_ms must be larger than 0".to_owned(),
            ));
        }
        Ok(EngineOptions {
            rule: self.rule.clone(),
            evaluation_time_limit: Some(Duration::from_millis(self.evaluation_time_limit_ms)),
        })
    }
}

/// Data that identifies the policy that an engine has in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyVersion {
    /// The rule that gives the decision.
    pub rule: String,
    /// The SHA-256 digest of the policy text and the data documents, in load order.
    pub digest: String,
    /// The names of the policy files, in load order.
    pub policies: Vec<String>,
    /// The names of the data documents, in load order.
    pub data: Vec<String>,
    /// The time at which the engine loaded the policy.
    pub loaded_at: DateTime<Utc>,
}

/// Why a set of sources did not load.
#[derive(Debug, ThisError)]
enum LoadError {
    #[error("cannot read the {what} {path}: {source}")]
    Read {
        what: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("the policy file {file} does not compile: {message}")]
    Compile { file: String, message: String },
    #[error("the policy does not compile or does not have the rule {rule}: {message}")]
    Prepare { rule: String, message: String },
    #[error("the data document {name} is not valid: {message}")]
    Data { name: String, message: String },
    #[error("the directory {path} has no *.rego file")]
    EmptyDirectory { path: String },
    #[error("the policy sources have no policy file")]
    NoPolicy,
    #[error("the rule path {rule} is not valid: a rule path starts with `data.`")]
    Rule { rule: String },
}

impl From<LoadError> for Error {
    fn from(error: LoadError) -> Self {
        Self::Config(error.to_string())
    }
}

/// Why the engine denied an action without a decision from the policy.
#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
enum FailClosed {
    #[error("The request cannot be encoded as the policy input: {message}.")]
    Input { message: String },
    #[error("The policy rule {rule} gave no result for this request.")]
    Undefined { rule: String },
    #[error("The evaluation of the policy rule {rule} failed: {message}.")]
    Evaluation { rule: String, message: String },
    #[error("The policy result is {found}, not an object.")]
    NotAnObject { found: &'static str },
    #[error("The policy result has no `effect` field.")]
    MissingEffect,
    #[error("The `{field}` field of the policy result has a value that is not valid: {found}.")]
    InvalidField { field: &'static str, found: String },
    #[error("The policy result has the unknown field `{field}`.")]
    UnknownField { field: String },
}

/// A decision that the policy made.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyResult {
    effect: PolicyEffect,
    tier: ActionTier,
    reasons: Vec<String>,
}

struct Active {
    sources: PolicySources,
    engine: regorus::Engine,
    version: PolicyVersion,
}

/// A policy engine that evaluates Rego in the process.
///
/// Refer to the [module documentation](self) for the decision rule and the fail-closed
/// behavior.
///
/// The engine is safe to share between tasks. Each evaluation uses its own copy of the
/// prepared policy, so evaluations do not wait for each other.
pub struct RegoPolicyEngine {
    options: EngineOptions,
    active: RwLock<Arc<Active>>,
}

impl fmt::Debug for RegoPolicyEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegoPolicyEngine")
            .field("options", &self.options)
            .field("version", &self.active().version)
            .finish()
    }
}

impl RegoPolicyEngine {
    /// Loads `sources` with the default settings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a file cannot be read, a policy file does not compile, a
    /// data document is not valid, or the policy does not have the decision rule. The
    /// message names the file.
    pub fn load(sources: PolicySources) -> Result<Self> {
        Self::load_with(sources, EngineOptions::default())
    }

    /// Loads `sources` with `options`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for the conditions that [`RegoPolicyEngine::load`] gives.
    pub fn load_with(sources: PolicySources, options: EngineOptions) -> Result<Self> {
        let (engine, version) = compile(&sources, &options)?;
        tracing::info!(digest = %version.digest, rule = %version.rule, "loaded the policy");
        Ok(Self {
            options,
            active: RwLock::new(Arc::new(Active {
                sources,
                engine,
                version,
            })),
        })
    }

    /// Loads the policy that `config` names.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a setting is not valid, and for the conditions that
    /// [`RegoPolicyEngine::load`] gives.
    pub fn from_config(config: &PolicyConfig) -> Result<Self> {
        Self::load_with(config.sources(), config.options()?)
    }

    /// Loads the present sources again and puts the result in use.
    ///
    /// The change is atomic. Each evaluation uses the old policy or the new policy, never a
    /// mixture.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the sources do not load. Then the policy that was in
    /// use stays in use.
    pub fn reload(&self) -> Result<PolicyVersion> {
        let sources = self.active().sources.clone();
        self.replace(sources)
    }

    /// Loads `sources` and puts them in use in place of the present sources.
    ///
    /// The change is atomic. A subsequent [`RegoPolicyEngine::reload`] reads `sources`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `sources` do not load. Then the policy that was in use
    /// stays in use.
    pub fn replace(&self, sources: PolicySources) -> Result<PolicyVersion> {
        let (engine, version) = compile(&sources, &self.options).inspect_err(|error| {
            tracing::warn!(%error, "rejected a policy that does not load; the policy in use did not change");
        })?;
        let active = Arc::new(Active {
            sources,
            engine,
            version: version.clone(),
        });
        *self.active.write().unwrap_or_else(PoisonError::into_inner) = active;
        tracing::info!(digest = %version.digest, rule = %version.rule, "loaded the policy");
        Ok(version)
    }

    /// Returns the data that identifies the policy in use.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        self.active().version.clone()
    }

    /// Returns the rule that gives the decision.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.options.rule
    }

    /// Evaluates the policy for `input`. This function does not wait.
    ///
    /// [`PolicyEngine::evaluate`] calls this function.
    ///
    /// The result is always a decision. If the policy gives no valid decision, the result
    /// has [`PolicyEffect::Deny`]. Refer to the [module documentation](self).
    #[must_use]
    pub fn decide(&self, input: &PolicyInput) -> PolicyDecision {
        let active = self.active();
        let evaluated_at = Utc::now();
        match self.run(&active, input) {
            Ok(result) => PolicyDecision {
                effect: result.effect,
                tier: result.tier,
                reasons: result.reasons,
                policy: Some(
                    self.options
                        .rule
                        .strip_prefix("data.")
                        .unwrap_or(&self.options.rule)
                        .to_owned(),
                ),
                evaluated_at,
            },
            Err(cause) => {
                tracing::warn!(
                    action = %input.action.id,
                    digest = %active.version.digest,
                    %cause,
                    "the policy gave no valid decision; the engine denied the action"
                );
                PolicyDecision {
                    effect: PolicyEffect::Deny,
                    tier: ActionTier::Gated,
                    reasons: vec![
                        cause.to_string(),
                        "The engine denies an action when the policy gives no valid decision."
                            .to_owned(),
                    ],
                    policy: Some(FAIL_CLOSED_POLICY.to_owned()),
                    evaluated_at,
                }
            }
        }
    }

    /// Gives `input` to a copy of the prepared policy and reads the decision rule.
    fn run(
        &self,
        active: &Active,
        input: &PolicyInput,
    ) -> std::result::Result<PolicyResult, FailClosed> {
        let document = serde_json::to_value(input).map_err(|error| FailClosed::Input {
            message: error.to_string(),
        })?;
        let mut engine = active.engine.clone();
        engine.set_input(regorus::Value::from(document));
        let value = engine.eval_rule(self.options.rule.clone());
        log_prints(&mut engine, input);
        match value {
            Ok(value) => read_result(&value, &self.options.rule, input.default_tier),
            Err(error) => Err(FailClosed::Evaluation {
                rule: self.options.rule.clone(),
                message: summarize(&error.to_string()),
            }),
        }
    }

    fn active(&self) -> Arc<Active> {
        Arc::clone(&self.active.read().unwrap_or_else(PoisonError::into_inner))
    }
}

#[async_trait]
impl PolicyEngine for RegoPolicyEngine {
    async fn evaluate(&self, input: &PolicyInput) -> Result<PolicyDecision> {
        Ok(self.decide(input))
    }
}

/// Sends the output of the `print` calls of the policy to the log at the debug level.
fn log_prints(engine: &mut regorus::Engine, input: &PolicyInput) {
    match engine.take_prints() {
        Ok(lines) => {
            for line in lines {
                tracing::debug!(
                    action = %input.action.id,
                    output = %clip(&line, MESSAGE_LIMIT),
                    "the policy printed a message"
                );
            }
        }
        Err(error) => {
            tracing::debug!(
                action = %input.action.id,
                error = %summarize(&error.to_string()),
                "cannot read the print output of the policy"
            );
        }
    }
}

/// Builds a prepared engine from `sources`.
fn compile(
    sources: &PolicySources,
    options: &EngineOptions,
) -> std::result::Result<(regorus::Engine, PolicyVersion), LoadError> {
    if !options.rule.starts_with("data.") {
        return Err(LoadError::Rule {
            rule: options.rule.clone(),
        });
    }
    let mut loader = Loader::new(options);
    for source in &sources.sources {
        match source {
            Source::PolicyText { name, text } => loader.add_policy(name, text)?,
            Source::PolicyFile(path) => loader.add_policy_file(path)?,
            Source::PolicyDirectory(path) => {
                for file in rego_files(path)? {
                    loader.add_policy_file(&file)?;
                }
            }
            Source::DataText { name, format, text } => loader.add_data(name, *format, text)?,
            Source::DataFile(path) => {
                let name = path.display().to_string();
                let format = data_format(path).ok_or_else(|| LoadError::Data {
                    name: name.clone(),
                    message: "the file extension must be .json, .yaml, or .yml".to_owned(),
                })?;
                let text = read_file("data file", path)?;
                loader.add_data(&name, format, &text)?;
            }
        }
    }
    loader.finish(&options.rule)
}

struct Loader {
    engine: regorus::Engine,
    digest: Sha256,
    policies: Vec<String>,
    data: Vec<String>,
}

impl Loader {
    fn new(options: &EngineOptions) -> Self {
        let mut engine = regorus::Engine::new();
        // An error in a built-in function must stop the evaluation. If it made the
        // expression undefined, a `deny` rule that uses the function would not match.
        engine.set_strict_builtin_errors(true);
        // Without this setting, a `print` call in a policy writes to the standard error
        // stream. The engine sends the output to the log instead.
        engine.set_gather_prints(true);
        if let Some(limit) = options.evaluation_time_limit {
            engine.set_execution_timer_config(ExecutionTimerConfig {
                limit,
                check_interval: TIMER_CHECK_INTERVAL,
            });
        }
        Self {
            engine,
            digest: Sha256::new(),
            policies: Vec::new(),
            data: Vec::new(),
        }
    }

    fn add_policy_file(&mut self, path: &Path) -> std::result::Result<(), LoadError> {
        let text = read_file("policy file", path)?;
        self.add_policy(&path.display().to_string(), &text)
    }

    fn add_policy(&mut self, name: &str, text: &str) -> std::result::Result<(), LoadError> {
        self.engine
            .add_policy(name.to_owned(), text.to_owned())
            .map_err(|error| LoadError::Compile {
                file: name.to_owned(),
                message: summarize(&error.to_string()),
            })?;
        self.absorb(b"policy", text);
        self.policies.push(name.to_owned());
        Ok(())
    }

    fn add_data(
        &mut self,
        name: &str,
        format: DataFormat,
        text: &str,
    ) -> std::result::Result<(), LoadError> {
        let invalid = |message: String| LoadError::Data {
            name: name.to_owned(),
            message,
        };
        let document: Value = match format {
            DataFormat::Json => {
                serde_json::from_str(text).map_err(|error| invalid(error.to_string()))?
            }
            DataFormat::Yaml => serde_saphyr::from_str(text)
                .map_err(|error| invalid(first_line(&error.to_string())))?,
        };
        if !document.is_object() {
            return Err(invalid(format!(
                "the top level is {}, not an object",
                type_name(&document)
            )));
        }
        self.engine
            .add_data(regorus::Value::from(document))
            .map_err(|error| invalid(summarize(&error.to_string())))?;
        self.absorb(b"data", text);
        self.data.push(name.to_owned());
        Ok(())
    }

    fn absorb(&mut self, kind: &[u8], text: &str) {
        self.digest.update(kind);
        self.digest
            .update(u64::try_from(text.len()).unwrap_or(u64::MAX).to_le_bytes());
        self.digest.update(text.as_bytes());
    }

    fn finish(
        mut self,
        rule: &str,
    ) -> std::result::Result<(regorus::Engine, PolicyVersion), LoadError> {
        if self.policies.is_empty() {
            return Err(LoadError::NoPolicy);
        }
        // This step finds the errors that the parser does not find, for example a variable
        // that is not safe. It also makes the engine ready, so that each copy of the engine
        // can evaluate immediately.
        self.engine
            .compile_with_entrypoint(&rule.into())
            .map_err(|error| LoadError::Prepare {
                rule: rule.to_owned(),
                message: summarize(&error.to_string()),
            })?;
        let version = PolicyVersion {
            rule: rule.to_owned(),
            digest: hex::encode(self.digest.finalize()),
            policies: self.policies,
            data: self.data,
            loaded_at: Utc::now(),
        };
        Ok((self.engine, version))
    }
}

fn read_file(what: &'static str, path: &Path) -> std::result::Result<String, LoadError> {
    fs::read_to_string(path).map_err(|source| LoadError::Read {
        what,
        path: path.display().to_string(),
        source,
    })
}

fn rego_files(directory: &Path) -> std::result::Result<Vec<PathBuf>, LoadError> {
    let read_error = |source| LoadError::Read {
        what: "policy directory",
        path: directory.display().to_string(),
        source,
    };
    let mut files = Vec::new();
    for entry in fs::read_dir(directory).map_err(read_error)? {
        let path = entry.map_err(read_error)?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rego")
            && path.is_file()
        {
            files.push(path);
        }
    }
    if files.is_empty() {
        return Err(LoadError::EmptyDirectory {
            path: directory.display().to_string(),
        });
    }
    files.sort();
    Ok(files)
}

fn data_format(path: &Path) -> Option<DataFormat> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "json" => Some(DataFormat::Json),
        "yaml" | "yml" => Some(DataFormat::Yaml),
        _ => None,
    }
}

/// Reads the value of the decision rule.
fn read_result(
    value: &regorus::Value,
    rule: &str,
    default_tier: ActionTier,
) -> std::result::Result<PolicyResult, FailClosed> {
    if matches!(value, regorus::Value::Undefined) {
        return Err(FailClosed::Undefined {
            rule: rule.to_owned(),
        });
    }
    let value = serde_json::to_value(value).map_err(|error| FailClosed::Evaluation {
        rule: rule.to_owned(),
        message: format!("the result cannot be encoded: {error}"),
    })?;
    interpret(&value, default_tier)
}

/// Checks the shape of the decision and reads its fields.
fn interpret(
    value: &Value,
    default_tier: ActionTier,
) -> std::result::Result<PolicyResult, FailClosed> {
    let Value::Object(fields) = value else {
        return Err(FailClosed::NotAnObject {
            found: type_name(value),
        });
    };
    if let Some(field) = fields
        .keys()
        .find(|key| !matches!(key.as_str(), "effect" | "tier" | "reasons"))
    {
        return Err(FailClosed::UnknownField {
            field: clip(field, VALUE_LIMIT),
        });
    }
    let effect = match fields.get("effect") {
        None => return Err(FailClosed::MissingEffect),
        Some(value) => named(value).ok_or_else(|| invalid_field("effect", value))?,
    };
    let tier = match fields.get("tier") {
        None => default_tier,
        Some(value) => named(value).ok_or_else(|| invalid_field("tier", value))?,
    };
    let reasons = match fields.get("reasons") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()
            .ok_or_else(|| FailClosed::InvalidField {
                field: "reasons",
                found: "a list with an item that is not a string".to_owned(),
            })?,
        Some(value) => {
            return Err(FailClosed::InvalidField {
                field: "reasons",
                found: type_name(value).to_owned(),
            });
        }
    };
    Ok(PolicyResult {
        effect,
        tier,
        reasons,
    })
}

/// Reads a string as one of the names that the contract gives to `T`.
fn named<T: serde::de::DeserializeOwned>(value: &Value) -> Option<T> {
    match value {
        Value::String(_) => serde_json::from_value(value.clone()).ok(),
        _ => None,
    }
}

fn invalid_field(field: &'static str, value: &Value) -> FailClosed {
    FailClosed::InvalidField {
        field,
        found: match value {
            Value::String(text) => format!("`{}`", clip(text, VALUE_LIMIT)),
            other => type_name(other).to_owned(),
        },
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

/// Returns no more than `limit` characters of `text`.
fn clip(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((end, _)) => format!("{}...", text.get(..end).unwrap_or_default()),
        None => text.to_owned(),
    }
}

fn first_line(text: &str) -> String {
    clip(
        text.lines().next().unwrap_or_default().trim(),
        MESSAGE_LIMIT,
    )
}

/// Makes one line from an error of the Rego interpreter.
///
/// The interpreter gives the location on a line that starts with `-->` and the cause on a
/// line that starts with `error:`. The other lines show the policy text.
fn summarize(text: &str) -> String {
    let location = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("-->"))
        .map(str::trim);
    let cause = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("error:"))
        .map(str::trim);
    let summary = match (cause, location) {
        (Some(cause), Some(location)) => format!("{cause} at {location}"),
        _ => text.split_whitespace().collect::<Vec<_>>().join(" "),
    };
    clip(summary.trim_end_matches('.'), MESSAGE_LIMIT)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn invalid(field: &'static str, found: &str) -> FailClosed {
        FailClosed::InvalidField {
            field,
            found: found.to_owned(),
        }
    }

    #[test]
    fn a_complete_decision_gives_its_three_fields() {
        let result = interpret(
            &json!({ "effect": "require_approval", "tier": "auto", "reasons": ["One.", "Two."] }),
            ActionTier::Gated,
        );
        assert_eq!(
            result,
            Ok(PolicyResult {
                effect: PolicyEffect::RequireApproval,
                tier: ActionTier::Auto,
                reasons: vec!["One.".to_owned(), "Two.".to_owned()],
            })
        );
    }

    #[test]
    fn the_optional_fields_take_their_defaults() {
        for default_tier in [ActionTier::Auto, ActionTier::Gated] {
            assert_eq!(
                interpret(&json!({ "effect": "allow" }), default_tier),
                Ok(PolicyResult {
                    effect: PolicyEffect::Allow,
                    tier: default_tier,
                    reasons: Vec::new(),
                })
            );
        }
    }

    #[test]
    fn each_shape_error_has_its_cause() {
        let cases = [
            (
                json!("allow"),
                FailClosed::NotAnObject { found: "a string" },
            ),
            (json!(true), FailClosed::NotAnObject { found: "a boolean" }),
            (
                json!(["allow"]),
                FailClosed::NotAnObject { found: "a list" },
            ),
            (json!(null), FailClosed::NotAnObject { found: "null" }),
            (json!({}), FailClosed::MissingEffect),
            (json!({ "tier": "auto" }), FailClosed::MissingEffect),
            (json!({ "effect": "permit" }), invalid("effect", "`permit`")),
            (json!({ "effect": "Allow" }), invalid("effect", "`Allow`")),
            (json!({ "effect": true }), invalid("effect", "a boolean")),
            (json!({ "effect": null }), invalid("effect", "null")),
            (
                json!({ "effect": "allow", "tier": "automatic" }),
                invalid("tier", "`automatic`"),
            ),
            (
                json!({ "effect": "allow", "tier": null }),
                invalid("tier", "null"),
            ),
            (
                json!({ "effect": "allow", "reasons": "One." }),
                invalid("reasons", "a string"),
            ),
            (
                json!({ "effect": "allow", "reasons": ["One.", 2] }),
                invalid("reasons", "a list with an item that is not a string"),
            ),
            (
                json!({ "effect": "allow", "teir": "gated" }),
                FailClosed::UnknownField {
                    field: "teir".to_owned(),
                },
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(
                interpret(&value, ActionTier::Auto),
                Err(expected),
                "{value}"
            );
        }
    }

    #[test]
    fn an_undefined_value_names_the_rule() {
        assert_eq!(
            read_result(&regorus::Value::Undefined, "data.x.y", ActionTier::Auto),
            Err(FailClosed::Undefined {
                rule: "data.x.y".to_owned()
            })
        );
    }

    #[test]
    fn a_long_policy_value_is_cut_in_the_reason() {
        let long = "x".repeat(VALUE_LIMIT + 10);
        let Err(FailClosed::InvalidField { found, .. }) =
            interpret(&json!({ "effect": long }), ActionTier::Auto)
        else {
            panic!("expected an invalid field");
        };
        assert_eq!(found, format!("`{}...`", "x".repeat(VALUE_LIMIT)));
        assert_eq!(clip("né", 1), "n...");
        assert_eq!(clip("né", 2), "né");
    }

    #[test]
    fn an_interpreter_error_becomes_one_line_with_the_location() {
        let text = "\n--> p.rego:3:40\n  |\n3 | decision := 1 / 0\n  |               ^\nerror: divide by zero";
        assert_eq!(summarize(text), "divide by zero at p.rego:3:40");
        assert_eq!(
            summarize("not a valid\n rule   path."),
            "not a valid rule path"
        );
    }

    #[test]
    fn the_data_format_comes_from_the_extension() {
        assert_eq!(
            data_format(Path::new("a/data.json")),
            Some(DataFormat::Json)
        );
        assert_eq!(data_format(Path::new("data.YAML")), Some(DataFormat::Yaml));
        assert_eq!(data_format(Path::new("data.yml")), Some(DataFormat::Yaml));
        assert_eq!(data_format(Path::new("data.toml")), None);
        assert_eq!(data_format(Path::new("data")), None);
    }

    #[test]
    fn the_debug_form_of_the_sources_does_not_show_the_text() {
        let sources = PolicySources::new()
            .policy_text("inline.rego", "package secret_policy_text")
            .data_text("inline.json", DataFormat::Json, r#"{"secret_data_text":1}"#);
        let shown = format!("{sources:?}");
        assert!(shown.contains("inline.rego"), "{shown}");
        assert!(shown.contains("inline.json"), "{shown}");
        assert!(!shown.contains("secret_policy_text"), "{shown}");
        assert!(!shown.contains("secret_data_text"), "{shown}");
    }
}
