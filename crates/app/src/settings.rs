//! The settings of the composition root.
//!
//! One [`Config`] document holds the sections of all subsystems. Each subsystem crate
//! defines the type of its section. This module reads each section, adds the settings that
//! only the composition root has, and checks the rules between the sections.
//!
//! | Section | Type | Necessary |
//! | --- | --- | --- |
//! | `modules` | [`ModuleSet`] | No |
//! | `telemetry` | `aegis_core::TelemetryConfig` | No |
//! | `bus` | [`BusConfig`] | Yes |
//! | `storage` | `kind = "memory"`, or `kind = "postgres"` with `aegis_storage::StorageConfig` | Yes |
//! | `audit` | `kind = "file"` with `path`, or `kind = "postgres"` | Yes |
//! | `model` | [`ModelConfig`] | No |
//! | `policy` | [`PolicyConfig`] | Yes |
//! | `rbac` | [`RbacConfig`] | No |
//! | `approval` | [`ApprovalRules`] | No |
//! | `detection` | `pack`, the keys of `aegis_detect::EngineConfig`, and `runner` | Yes |
//! | `agents` | `goal`, `monitor_events`, and the keys of [`RuntimeConfig`] | No |
//! | `response` | `dry_run`, `playbooks`, `playbook_dir`, `graph`, `webhook`, `routes` | No |
//! | `sources` | A list of [`SourceConfig`] | No |
//! | `ingest` | `checkpoint_dir` and `retry` | No |
//! | `plugins` | `dir` and `limits` | No |
//!
//! A section name that is not in this table is an error. Each section rejects a key that
//! it does not know.
//!
//! # Paths
//!
//! A relative path in a section starts at the base directory. The command-line program
//! uses the directory of the configuration file. [`App::build`](crate::App::build) uses the
//! working directory of the process.

use std::path::{Path, PathBuf};

use aegis_agents::{
    AnalystConfig, DeceptionConfig, HunterConfig, MonitorConfig, ResponderConfig, RuntimeConfig,
    RuntimeLimits,
};
pub use aegis_bus::BusKind;
use aegis_bus::{BusConfig, NatsAuth};
use aegis_contracts::{AgentRole, Error, Result};
use aegis_core::{Config, Module, ModuleSet, TelemetryConfig};
use aegis_detect::{
    BusRunnerConfig, CorrelatorConfig, EngineConfig, LlmTriageConfig, VelocityConfig,
};
use aegis_ingest::{RetryPolicy, SourceConfig};
use aegis_model::ModelConfig;
use aegis_policy::{ApprovalRules, FileAuditLogConfig, PolicyConfig, RbacConfig};
use aegis_respond::{GraphConfig, Route, WebhookConfig};
use serde::{Deserialize, Serialize};

/// The names of the sections that the composition root reads.
pub const SECTIONS: [&str; 15] = [
    "modules",
    "telemetry",
    "bus",
    "storage",
    "audit",
    "model",
    "policy",
    "rbac",
    "approval",
    "detection",
    "agents",
    "response",
    "sources",
    "ingest",
    "plugins",
];

/// The default goal of the operator.
pub const DEFAULT_GOAL: &str = "Keep the environment of the operator safe.";

/// Which events the bridge gives to the Monitor agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorEvents {
    /// Only the events that caused a detection. This is the default.
    #[default]
    Detected,
    /// All events.
    All,
    /// No events.
    None,
}

/// How the composition root runs the playbooks of the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookMode {
    /// No playbook runs.
    Off,
    /// Each matching playbook runs as a dry run. This is the default.
    #[default]
    DryRun,
    /// Each matching playbook runs with changes, if policy permits them.
    Live,
}

/// Where the incidents, the Defensive Graph, the embeddings, and the approvals are.
#[derive(Clone)]
pub enum StorageSettings {
    /// In the memory of the process. The data goes away when the process stops.
    Memory,
    /// In PostgreSQL.
    #[cfg(feature = "postgres")]
    Postgres(aegis_storage::StorageConfig),
}

impl StorageSettings {
    /// Returns the value of `storage.kind`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Memory => "memory",
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => "postgres",
        }
    }
}

/// Where the audit log is.
#[derive(Debug, Clone)]
pub enum AuditSettings {
    /// One append-only JSON Lines file.
    File(FileAuditLogConfig),
    /// The audit table of the PostgreSQL store. `storage.kind` must be `postgres`.
    Postgres,
}

/// The `[detection]` section.
#[derive(Debug, Clone)]
pub struct DetectionSettings {
    /// The directory of the rule pack.
    pub pack: PathBuf,
    /// The settings of the detection engine.
    pub engine: EngineConfig,
    /// The settings of the bus runner of the engine.
    pub runner: BusRunnerConfig,
}

/// The `[agents]` section.
#[derive(Debug, Clone)]
pub struct AgentSettings {
    /// The goal of the operator, in natural language.
    pub goal: String,
    /// Which events the Monitor agent gets.
    pub monitor_events: MonitorEvents,
    /// The configuration of the agent runtime. `enabled_roles` holds only the roles whose
    /// module is in the module set.
    pub runtime: RuntimeConfig,
}

/// The `[response]` section.
#[derive(Clone)]
pub struct ResponseSettings {
    /// With `true`, the dispatcher sets `dry_run` on each request. The default is `true`.
    pub dry_run: bool,
    /// With `true` and `dry_run`, an action type that has no connector goes to the
    /// simulation connector. The default is `true`.
    pub simulate_missing_connectors: bool,
    /// How the playbooks run. The default is [`PlaybookMode::DryRun`].
    pub playbooks: PlaybookMode,
    /// The directory of the playbooks.
    pub playbook_dir: Option<PathBuf>,
    /// The Microsoft Graph connector.
    pub graph: Option<GraphConfig>,
    /// The webhook connector.
    pub webhook: Option<WebhookConfig>,
    /// The routing table of the action registry.
    pub routes: Vec<Route>,
    /// The data that the policy reads as `input.environment`.
    pub environment: serde_json::Value,
    /// The maximum time for one connector call, in seconds.
    pub execution_timeout_seconds: u64,
}

/// The `[ingest]` section.
#[derive(Debug, Clone, Default)]
pub struct IngestSettings {
    /// The directory of the checkpoint files. With `None`, the cursors are in memory.
    pub checkpoint_dir: Option<PathBuf>,
    /// The retry rules of the ingestion runners.
    pub retry: RetryPolicy,
}

/// The limits of the plugin sandbox that the configuration can change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PluginLimits {
    /// The total linear memory of one plugin instance, in bytes.
    pub max_memory_bytes: Option<usize>,
    /// The time of one call into a plugin, in seconds.
    pub call_timeout_seconds: Option<u64>,
    /// The calls that run in one plugin at the same time.
    pub max_concurrent_calls: Option<usize>,
    /// The time of one HTTP request of a plugin, in seconds.
    pub http_timeout_seconds: Option<u64>,
    /// With `true`, a manifest without `sha256` does not load.
    pub require_sha256: Option<bool>,
}

/// The `[plugins]` section.
#[derive(Debug, Clone)]
pub struct PluginSettings {
    /// The directory of the plugin manifests.
    pub dir: PathBuf,
    /// The limits of the sandbox.
    pub limits: PluginLimits,
}

/// All settings of one AEGIS process.
#[derive(Clone)]
pub struct Settings {
    /// The directory that relative paths start at.
    pub base_dir: PathBuf,
    /// The modules that the process runs.
    pub modules: ModuleSet,
    /// The `[telemetry]` section.
    pub telemetry: TelemetryConfig,
    /// The `[bus]` section.
    pub bus: BusConfig,
    /// The `[storage]` section.
    pub storage: StorageSettings,
    /// The `[audit]` section.
    pub audit: AuditSettings,
    /// The `[model]` section. `None` means that the process has no model.
    pub model: Option<ModelConfig>,
    /// The `[policy]` section.
    pub policy: PolicyConfig,
    /// The `[rbac]` section.
    pub rbac: RbacConfig,
    /// The `[approval]` section.
    pub approval: ApprovalRules,
    /// The `[detection]` section.
    pub detection: DetectionSettings,
    /// The `[agents]` section.
    pub agents: AgentSettings,
    /// The `[response]` section.
    pub response: ResponseSettings,
    /// The `[[sources]]` list.
    pub sources: Vec<SourceConfig>,
    /// The `[ingest]` section.
    pub ingest: IngestSettings,
    /// The `[plugins]` section.
    pub plugins: Option<PluginSettings>,
}

/// A table that accepts no key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoKeys {}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StorageSection {
    Memory(NoKeys),
    #[cfg(feature = "postgres")]
    Postgres(aegis_storage::StorageConfig),
    #[cfg(not(feature = "postgres"))]
    Postgres(serde::de::IgnoredAny),
}

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AuditBackend {
    #[default]
    File,
    Postgres,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditSection {
    #[serde(default)]
    kind: AuditBackend,
    path: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectionSection {
    pack: PathBuf,
    #[serde(default)]
    velocity: VelocityConfig,
    #[serde(default)]
    correlator: CorrelatorConfig,
    #[serde(default)]
    triage: LlmTriageConfig,
    #[serde(default)]
    runner: BusRunnerConfig,
}

/// The keys of [`RuntimeConfig`] and the keys of the composition root, in one table.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AgentsSection {
    goal: String,
    monitor_events: MonitorEvents,
    dry_run: bool,
    enabled_roles: Vec<AgentRole>,
    tick_interval_seconds: u64,
    bus_consumer: Option<String>,
    limits: RuntimeLimits,
    monitor: MonitorConfig,
    hunter: HunterConfig,
    analyst: AnalystConfig,
    responder: ResponderConfig,
    deception: DeceptionConfig,
}

impl Default for AgentsSection {
    fn default() -> Self {
        let RuntimeConfig {
            dry_run,
            enabled_roles,
            tick_interval_seconds,
            bus_consumer,
            limits,
            monitor,
            hunter,
            analyst,
            responder,
            deception,
        } = RuntimeConfig::default();
        Self {
            goal: DEFAULT_GOAL.to_owned(),
            monitor_events: MonitorEvents::default(),
            dry_run,
            enabled_roles,
            tick_interval_seconds,
            bus_consumer,
            limits,
            monitor,
            hunter,
            analyst,
            responder,
            deception,
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResponseSection {
    dry_run: bool,
    simulate_missing_connectors: bool,
    playbooks: PlaybookMode,
    playbook_dir: Option<PathBuf>,
    graph: Option<GraphConfig>,
    webhook: Option<WebhookConfig>,
    routes: Vec<Route>,
    environment: serde_json::Value,
    execution_timeout_seconds: u64,
}

impl Default for ResponseSection {
    fn default() -> Self {
        Self {
            dry_run: true,
            simulate_missing_connectors: true,
            playbooks: PlaybookMode::default(),
            playbook_dir: None,
            graph: None,
            webhook: None,
            routes: Vec::new(),
            environment: serde_json::Value::Null,
            execution_timeout_seconds: 120,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct IngestSection {
    checkpoint_dir: Option<PathBuf>,
    retry: RetryPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsSection {
    dir: PathBuf,
    #[serde(default)]
    limits: PluginLimits,
}

/// Returns the module that must be in the module set for a built-in agent role.
///
/// The Supervisor has no module of its own. It runs when one agent module or more is in
/// the set. A custom role has no module and always runs.
fn module_of(role: &AgentRole) -> Option<Module> {
    match role {
        AgentRole::Monitor => Some(Module::Monitor),
        AgentRole::Hunter => Some(Module::Hunter),
        AgentRole::Analyst => Some(Module::Analyst),
        AgentRole::Responder => Some(Module::Responder),
        AgentRole::Deception => Some(Module::Deception),
        AgentRole::Reporter => Some(Module::Reporter),
        AgentRole::Supervisor | AgentRole::Custom(_) => None,
    }
}

/// Returns the roles of `configured` that the module set permits, in the same order.
fn permitted_roles(configured: &[AgentRole], modules: &ModuleSet) -> Vec<AgentRole> {
    let mut roles: Vec<AgentRole> = configured
        .iter()
        .filter(|role| module_of(role).is_some_and(|module| modules.contains(module)))
        .cloned()
        .collect();
    if roles.is_empty() {
        // No agent module is in the set: the process runs no agent.
        return roles;
    }
    let mut all = Vec::with_capacity(configured.len());
    for role in configured {
        if module_of(role).is_none() || roles.contains(role) {
            all.push(role.clone());
        }
    }
    roles.clear();
    for role in all {
        if !roles.contains(&role) {
            roles.push(role);
        }
    }
    roles
}

/// Returns the value of a section, or records the problem of the section.
fn take<T>(result: Result<T>, problems: &mut Vec<Error>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            problems.push(error);
            None
        }
    }
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn resolve_in_place(base: &Path, path: &mut PathBuf) {
    *path = resolve(base, path);
}

fn config_error(section: &str, problem: impl std::fmt::Display) -> Error {
    Error::Config(format!("the section `{section}` is not valid: {problem}"))
}

impl Settings {
    /// Reads all sections of `config`.
    ///
    /// `base_dir` is the directory that relative paths start at. `extra_sections` holds
    /// the names of sections that a different component of the process reads.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] in these conditions. The message names the section.
    ///
    /// - A necessary section is missing.
    /// - A section does not match its type, or it has a key that is not known.
    /// - The document has a section that no component reads.
    /// - A value breaks a rule between two sections. For example, `audit.kind` is
    ///   `postgres` and `storage.kind` is `memory`.
    /// - A section needs a Cargo feature that this build does not have.
    ///
    /// The error is the first problem. [`Settings::read`] returns all problems.
    pub fn from_config(
        config: &Config,
        base_dir: &Path,
        extra_sections: &[String],
    ) -> Result<Self> {
        Self::first_problem(Self::read_sections(config, base_dir, extra_sections, None))
    }

    /// Reads all sections of `config`, but uses `modules` in place of the `[modules]`
    /// section. The agent roles follow `modules`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Settings::from_config`].
    pub fn from_config_with_modules(
        config: &Config,
        base_dir: &Path,
        extra_sections: &[String],
        modules: ModuleSet,
    ) -> Result<Self> {
        Self::first_problem(Self::read_sections(
            config,
            base_dir,
            extra_sections,
            Some(modules),
        ))
    }

    fn first_problem(read: std::result::Result<Self, Vec<Error>>) -> Result<Self> {
        read.map_err(|mut problems| {
            if problems.is_empty() {
                Error::Config("the configuration is not valid".to_owned())
            } else {
                problems.remove(0)
            }
        })
    }

    /// Reads all sections of `config` and collects the problems of all sections.
    ///
    /// The function does not stop at the first section that is not valid. Thus an operator
    /// sees each problem in one run.
    ///
    /// # Errors
    ///
    /// Returns one error for each problem, in the order of [`SECTIONS`]. The list has one
    /// error or more.
    pub fn read(
        config: &Config,
        base_dir: &Path,
        extra_sections: &[String],
    ) -> std::result::Result<Self, Vec<Error>> {
        Self::read_sections(config, base_dir, extra_sections, None)
    }

    fn read_sections(
        config: &Config,
        base_dir: &Path,
        extra_sections: &[String],
        modules_override: Option<ModuleSet>,
    ) -> std::result::Result<Self, Vec<Error>> {
        let mut problems: Vec<Error> = Vec::new();

        let unknown: Vec<&str> = config
            .section_names()
            .into_iter()
            .filter(|name| {
                !SECTIONS.contains(name) && !extra_sections.iter().any(|extra| extra == name)
            })
            .collect();
        if !unknown.is_empty() {
            problems.push(Error::Config(format!(
                "the configuration has sections that AEGIS does not know: {}. The known \
                 sections are: {}",
                unknown.join(", "),
                SECTIONS.join(", ")
            )));
        }

        let modules = match modules_override {
            Some(modules) => Some(modules),
            None => take(ModuleSet::from_config(config), &mut problems),
        };
        let telemetry = take(TelemetryConfig::from_config(config), &mut problems);
        let bus = take(Self::bus(config, base_dir), &mut problems);
        let storage = take(Self::storage(config), &mut problems);
        let audit = take(
            Self::audit(config, base_dir, storage.as_ref()),
            &mut problems,
        );
        let model = take(Self::model(config), &mut problems);
        let policy = take(Self::policy(config, base_dir), &mut problems);
        let rbac = take(
            config.section_or_default::<RbacConfig>("rbac"),
            &mut problems,
        );
        let approval = take(
            config.section_or_default::<ApprovalRules>("approval"),
            &mut problems,
        );
        let detection = take(Self::detection(config, base_dir), &mut problems);
        let agents = take(
            Self::agents(
                config,
                modules.as_ref(),
                detection.as_ref().map(|detection| &detection.runner),
            ),
            &mut problems,
        );
        let response = take(Self::response(config, base_dir), &mut problems);
        let sources = take(Self::sources(config, base_dir), &mut problems);
        let ingest = take(Self::ingest(config, base_dir), &mut problems);
        let plugins = take(Self::plugins(config, base_dir), &mut problems);

        if !problems.is_empty() {
            return Err(problems);
        }
        let settings = (|| {
            Some(Self {
                base_dir: base_dir.to_path_buf(),
                modules: modules?,
                telemetry: telemetry?,
                bus: bus?,
                storage: storage?,
                audit: audit?,
                model: model?,
                policy: policy?,
                rbac: rbac?,
                approval: approval?,
                detection: detection?,
                agents: agents?,
                response: response?,
                sources: sources?,
                ingest: ingest?,
                plugins: plugins?,
            })
        })();
        settings.ok_or_else(|| vec![Error::Config("the configuration is not valid".to_owned())])
    }

    fn model(config: &Config) -> Result<Option<ModelConfig>> {
        if config.has_section("model") {
            Ok(Some(config.section("model")?))
        } else {
            Ok(None)
        }
    }

    fn policy(config: &Config, base_dir: &Path) -> Result<PolicyConfig> {
        let mut policy: PolicyConfig = config.section("policy")?;
        for path in policy.paths.iter_mut().chain(policy.data.iter_mut()) {
            resolve_in_place(base_dir, path);
        }
        Ok(policy)
    }

    fn sources(config: &Config, base_dir: &Path) -> Result<Vec<SourceConfig>> {
        let mut sources: Vec<SourceConfig> = config.section_or_default("sources")?;
        for source in &mut sources {
            if let SourceConfig::File(file) = source {
                resolve_in_place(base_dir, &mut file.path);
            }
        }
        Ok(sources)
    }

    fn ingest(config: &Config, base_dir: &Path) -> Result<IngestSettings> {
        let ingest: IngestSection = config.section_or_default("ingest")?;
        Ok(IngestSettings {
            checkpoint_dir: ingest.checkpoint_dir.map(|path| resolve(base_dir, &path)),
            retry: ingest.retry,
        })
    }

    fn bus(config: &Config, base_dir: &Path) -> Result<BusConfig> {
        let mut bus: BusConfig = config.section("bus")?;
        let tls = &mut bus.nats.tls;
        for path in [
            &mut tls.ca_file,
            &mut tls.client_cert_file,
            &mut tls.client_key_file,
        ]
        .into_iter()
        .flatten()
        {
            resolve_in_place(base_dir, path);
        }
        if let NatsAuth::CredentialsFile { path } = &mut bus.nats.auth {
            resolve_in_place(base_dir, path);
        }
        bus.validate()
            .map_err(|error| section_error("bus", error))?;
        Ok(bus)
    }

    fn storage(config: &Config) -> Result<StorageSettings> {
        match config.section::<StorageSection>("storage")? {
            StorageSection::Memory(NoKeys {}) => Ok(StorageSettings::Memory),
            #[cfg(feature = "postgres")]
            StorageSection::Postgres(storage) => Ok(StorageSettings::Postgres(storage)),
            #[cfg(not(feature = "postgres"))]
            StorageSection::Postgres(_) => Err(config_error(
                "storage",
                "kind = \"postgres\" needs the Cargo feature `postgres`, and this build does \
                 not have it",
            )),
        }
    }

    /// Reads the `[audit]` section. With `None` for `storage`, the storage section is not
    /// valid, and the rule between the two sections is not examined.
    fn audit(
        config: &Config,
        base_dir: &Path,
        storage: Option<&StorageSettings>,
    ) -> Result<AuditSettings> {
        let section: AuditSection = config.section("audit")?;
        match (section.kind, section.path) {
            (AuditBackend::File, Some(path)) => Ok(AuditSettings::File(FileAuditLogConfig {
                path: resolve(base_dir, &path),
            })),
            (AuditBackend::File, None) => Err(config_error(
                "audit",
                "kind = \"file\" needs the key `path`",
            )),
            (AuditBackend::Postgres, Some(_)) => Err(config_error(
                "audit",
                "kind = \"postgres\" does not use the key `path`",
            )),
            (AuditBackend::Postgres, None) => match storage {
                Some(StorageSettings::Memory) => Err(config_error(
                    "audit",
                    "kind = \"postgres\" needs storage.kind = \"postgres\"",
                )),
                #[cfg(feature = "postgres")]
                Some(StorageSettings::Postgres(_)) => Ok(AuditSettings::Postgres),
                None => Ok(AuditSettings::Postgres),
            },
        }
    }

    fn detection(config: &Config, base_dir: &Path) -> Result<DetectionSettings> {
        let section: DetectionSection = config.section("detection")?;
        Ok(DetectionSettings {
            pack: resolve(base_dir, &section.pack),
            engine: EngineConfig {
                velocity: section.velocity,
                correlator: section.correlator,
                triage: section.triage,
            },
            runner: section.runner,
        })
    }

    /// Reads the `[agents]` section. With `None` for `modules` or `runner`, that section
    /// is not valid, and the rules that need it are not examined.
    fn agents(
        config: &Config,
        modules: Option<&ModuleSet>,
        runner: Option<&BusRunnerConfig>,
    ) -> Result<AgentSettings> {
        let section: AgentsSection = config.section_or_default("agents")?;
        if section.goal.trim().is_empty() {
            return Err(config_error("agents", "the key `goal` must not be empty"));
        }
        let enabled_roles = match modules {
            Some(modules) => permitted_roles(&section.enabled_roles, modules),
            None => section.enabled_roles.clone(),
        };
        let runtime = RuntimeConfig {
            dry_run: section.dry_run,
            enabled_roles,
            tick_interval_seconds: section.tick_interval_seconds,
            bus_consumer: section.bus_consumer,
            limits: section.limits,
            monitor: section.monitor,
            hunter: section.hunter,
            analyst: section.analyst,
            responder: section.responder,
            deception: section.deception,
        };
        runtime
            .validate()
            .map_err(|error| section_error("agents", error))?;
        // One durable name reads one pattern. The agent runtime adds `-tasks` and
        // `-incidents` to its name, and the detection runner reads the events.
        if let (Some(consumer), Some(runner)) = (&runtime.bus_consumer, runner) {
            let taken = [format!("{consumer}-tasks"), format!("{consumer}-incidents")];
            if taken.contains(&runner.durable_name) {
                return Err(config_error(
                    "detection",
                    format!(
                        "runner.durable_name is `{}`, which is a durable name of the agent \
                         runtime (agents.bus_consumer). Use a different name",
                        runner.durable_name
                    ),
                ));
            }
        }
        Ok(AgentSettings {
            goal: section.goal,
            monitor_events: section.monitor_events,
            runtime,
        })
    }

    fn response(config: &Config, base_dir: &Path) -> Result<ResponseSettings> {
        let section: ResponseSection = config.section_or_default("response")?;
        if section.execution_timeout_seconds == 0 {
            return Err(config_error(
                "response",
                "the key `execution_timeout_seconds` must be larger than 0",
            ));
        }
        Ok(ResponseSettings {
            dry_run: section.dry_run,
            simulate_missing_connectors: section.simulate_missing_connectors,
            playbooks: section.playbooks,
            playbook_dir: section.playbook_dir.map(|path| resolve(base_dir, &path)),
            graph: section.graph,
            webhook: section.webhook,
            routes: section.routes,
            environment: section.environment,
            execution_timeout_seconds: section.execution_timeout_seconds,
        })
    }

    fn plugins(config: &Config, base_dir: &Path) -> Result<Option<PluginSettings>> {
        if !config.has_section("plugins") {
            return Ok(None);
        }
        let section: PluginsSection = config.section("plugins")?;
        if cfg!(not(feature = "plugins")) {
            return Err(config_error(
                "plugins",
                "the section needs the Cargo feature `plugins`, and this build does not have it",
            ));
        }
        Ok(Some(PluginSettings {
            dir: resolve(base_dir, &section.dir),
            limits: section.limits,
        }))
    }
}

/// Adds the name of a section to an error of a subsystem. The variant stays the same.
pub(crate) fn section_error(section: &str, error: Error) -> Error {
    let prefix = |message: String| format!("the section `{section}` is not valid: {message}");
    let context = |message: String| format!("[{section}] {message}");
    match error {
        Error::Config(message) => {
            if message.contains(&format!("the section `{section}`")) {
                Error::Config(message)
            } else {
                Error::Config(prefix(message))
            }
        }
        Error::InvalidInput(message) => Error::Config(prefix(message)),
        Error::NotFound(message) => Error::Config(prefix(format!("not found: {message}"))),
        Error::Unauthorized(message) => Error::Unauthorized(context(message)),
        Error::Denied(message) => Error::Denied(context(message)),
        Error::Unsupported(message) => Error::Unsupported(context(message)),
        Error::Unavailable(message) => Error::Unavailable(context(message)),
        Error::RateLimited(message) => Error::RateLimited(context(message)),
        Error::Timeout(message) => Error::Timeout(context(message)),
        Error::Refused(message) => Error::Refused(context(message)),
        Error::BudgetExceeded(message) => Error::BudgetExceeded(context(message)),
        Error::Serialization(message) => Error::Serialization(context(message)),
        Error::Integrity(message) => Error::Integrity(context(message)),
        Error::Other {
            context: operation,
            source,
        } => Error::Other {
            context: context(operation),
            source,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const MINIMAL: &str = r#"
        [bus]
        kind = "memory"

        [storage]
        kind = "memory"

        [audit]
        path = "data/audit.jsonl"

        [policy]
        paths = ["policies/default.rego"]

        [detection]
        pack = "detections/aegis-identity"
    "#;

    fn read(text: &str) -> Result<Settings> {
        let config = Config::from_toml_str(text)?;
        Settings::from_config(&config, Path::new("/etc/aegis"), &[])
    }

    fn config_message(text: &str) -> String {
        match read(text) {
            Err(Error::Config(message)) => message,
            Err(other) => panic!("expected a configuration error, found {other:?}"),
            Ok(_) => panic!("the configuration must not be valid"),
        }
    }

    fn with(extra: &str) -> String {
        format!("{MINIMAL}\n{extra}")
    }

    #[test]
    fn a_minimal_configuration_gets_the_safe_defaults() {
        let settings = read(MINIMAL).unwrap();
        assert_eq!(settings.modules, ModuleSet::monitoring_only());
        assert_eq!(settings.storage.kind(), "memory");
        assert!(settings.model.is_none());
        assert!(settings.response.dry_run);
        assert!(settings.response.simulate_missing_connectors);
        assert_eq!(settings.response.playbooks, PlaybookMode::DryRun);
        assert_eq!(settings.response.playbook_dir, None);
        assert!(settings.agents.runtime.dry_run);
        assert_eq!(settings.agents.monitor_events, MonitorEvents::Detected);
        assert_eq!(settings.agents.goal, DEFAULT_GOAL);
        assert!(settings.sources.is_empty());
        assert_eq!(settings.ingest.checkpoint_dir, None);
        assert!(settings.plugins.is_none());
        assert_eq!(settings.approval, ApprovalRules::default());
        assert_eq!(settings.rbac, RbacConfig::default());
    }

    #[test]
    fn relative_paths_start_at_the_base_directory_and_absolute_paths_stay() {
        let settings = read(&with(
            r#"
            [response]
            playbook_dir = "/srv/playbooks"

            [ingest]
            checkpoint_dir = "data/checkpoints"

            [[sources]]
            type = "file"
            name = "replay"
            path = "events.jsonl"
            "#,
        ))
        .unwrap();
        assert_eq!(
            settings.policy.paths,
            [PathBuf::from("/etc/aegis/policies/default.rego")]
        );
        assert_eq!(
            settings.detection.pack,
            PathBuf::from("/etc/aegis/detections/aegis-identity")
        );
        match &settings.audit {
            AuditSettings::File(file) => {
                assert_eq!(file.path, PathBuf::from("/etc/aegis/data/audit.jsonl"));
            }
            AuditSettings::Postgres => panic!("the audit log must be a file"),
        }
        assert_eq!(
            settings.response.playbook_dir,
            Some(PathBuf::from("/srv/playbooks"))
        );
        assert_eq!(
            settings.ingest.checkpoint_dir,
            Some(PathBuf::from("/etc/aegis/data/checkpoints"))
        );
        assert_eq!(settings.sources.len(), 1);
        match &settings.sources[0] {
            SourceConfig::File(file) => {
                assert_eq!(file.path, PathBuf::from("/etc/aegis/events.jsonl"));
            }
            SourceConfig::Entra(_) => panic!("the source must be a file source"),
        }
    }

    #[test]
    fn each_necessary_section_is_named_when_it_is_missing() {
        for section in ["bus", "storage", "audit", "policy", "detection"] {
            let text: String = MINIMAL
                .split("\n\n")
                .filter(|block| !block.trim_start().starts_with(&format!("[{section}]")))
                .collect::<Vec<_>>()
                .join("\n\n");
            assert_eq!(
                config_message(&text),
                format!("the section `{section}` is missing"),
            );
        }
    }

    #[test]
    fn a_section_that_no_component_reads_is_an_error() {
        let message = config_message(&with("[respones]\ndry_run = false\n"));
        assert!(
            message
                .starts_with("the configuration has sections that AEGIS does not know: respones."),
            "{message}"
        );

        // A component can declare its own section.
        let config = Config::from_toml_str(&with("[api]\nlisten = \"127.0.0.1:8080\"\n")).unwrap();
        let settings =
            Settings::from_config(&config, Path::new("/etc/aegis"), &["api".to_owned()]).unwrap();
        assert!(settings.response.dry_run);
    }

    #[test]
    fn an_unknown_key_is_an_error_that_names_the_section_and_the_key() {
        for (section, text) in [
            ("response", "[response]\ndry_runs = false\n"),
            ("agents", "[agents]\nmonitor_event = \"all\"\n"),
            ("ingest", "[ingest]\ncheckpoints = \"x\"\n"),
            ("approval", "[approval]\nfour_eye = false\n"),
        ] {
            let message = config_message(&with(text));
            assert!(
                message.starts_with(&format!("the section `{section}` is not valid:")),
                "{message}"
            );
            assert!(message.contains("unknown field"), "{message}");
        }
        let message = config_message(&MINIMAL.replace(
            "pack = \"detections/aegis-identity\"",
            "pack = \"detections/aegis-identity\"\npacks = 2",
        ));
        assert!(
            message.starts_with("the section `detection` is not valid:"),
            "{message}"
        );
        let message = config_message(&MINIMAL.replace(
            "kind = \"memory\"\n\n        [audit]",
            "kind = \"memory\"\nurl = \"x\"\n\n        [audit]",
        ));
        assert!(
            message.starts_with("the section `storage` is not valid:"),
            "{message}"
        );
    }

    #[test]
    fn read_collects_the_problems_of_all_sections() {
        let text = MINIMAL
            .replace(
                "[bus]\n        kind = \"memory\"",
                "[bus]\nkind = \"carrier-pigeon\"",
            )
            .replace(
                "paths = [\"policies/default.rego\"]",
                "path = \"policies/default.rego\"",
            )
            + "\n[response]\nplaybooks = \"sometimes\"\n\n[extra]\nkey = 1\n";
        let config = Config::from_toml_str(&text).unwrap();
        let problems = match Settings::read(&config, Path::new("/etc/aegis"), &[]) {
            Err(problems) => problems,
            Ok(_) => panic!("the configuration must not be valid"),
        };
        let messages: Vec<String> = problems
            .iter()
            .map(|problem| match problem {
                Error::Config(message) => message.clone(),
                other => panic!("expected a configuration error, found {other:?}"),
            })
            .collect();
        assert_eq!(messages.len(), 4, "{messages:?}");
        assert!(
            messages[0]
                .starts_with("the configuration has sections that AEGIS does not know: extra."),
            "{}",
            messages[0]
        );
        assert!(
            messages[1].starts_with("the section `bus` is not valid:"),
            "{}",
            messages[1]
        );
        assert!(
            messages[2].starts_with("the section `policy` is not valid:"),
            "{}",
            messages[2]
        );
        assert!(
            messages[3].starts_with("the section `response` is not valid:"),
            "{}",
            messages[3]
        );
        // `from_config` gives the first problem.
        let first = config_message(&text);
        assert_eq!(first, messages[0]);
    }

    #[test]
    fn the_agent_keys_and_the_runtime_keys_share_one_table() {
        let settings = read(&with(
            r#"
            [modules]
            enabled = ["ingest", "detection", "monitor", "analyst", "responder"]

            [agents]
            goal = "Keep the tenant contoso safe."
            monitor_events = "all"
            dry_run = false
            tick_interval_seconds = 0
            bus_consumer = "soc-agents"

            [agents.limits]
            max_concurrency = 2

            [agents.responder]
            refine_with_model = false
            "#,
        ))
        .unwrap();
        let agents = &settings.agents;
        assert_eq!(agents.goal, "Keep the tenant contoso safe.");
        assert_eq!(agents.monitor_events, MonitorEvents::All);
        assert!(!agents.runtime.dry_run);
        assert_eq!(agents.runtime.tick_interval_seconds, 0);
        assert_eq!(agents.runtime.bus_consumer.as_deref(), Some("soc-agents"));
        assert_eq!(agents.runtime.limits.max_concurrency, 2);
        assert!(!agents.runtime.responder.refine_with_model);
        // The roles follow the module set. The supervisor needs no module of its own.
        assert_eq!(
            agents.runtime.enabled_roles,
            [
                AgentRole::Supervisor,
                AgentRole::Monitor,
                AgentRole::Analyst,
                AgentRole::Responder
            ]
        );
    }

    #[test]
    fn the_module_set_selects_the_agent_roles() {
        let default_roles = read(MINIMAL).unwrap().agents.runtime.enabled_roles;
        assert_eq!(default_roles, [AgentRole::Supervisor, AgentRole::Monitor]);

        let none = read(&with("[modules]\nenabled = [\"ingest\", \"detection\"]\n")).unwrap();
        assert_eq!(none.agents.runtime.enabled_roles, []);

        // A role that the operator removed stays off, also when its module is in the set.
        let removed = read(&with(
            "[modules]\nenabled = [\"detection\", \"monitor\", \"analyst\"]\n\n[agents]\n\
             enabled_roles = [\"monitor\"]\n",
        ))
        .unwrap();
        assert_eq!(removed.agents.runtime.enabled_roles, [AgentRole::Monitor]);
    }

    #[test]
    fn a_value_that_is_not_valid_names_its_section() {
        let message = config_message(&with("[agents]\ngoal = \"  \"\n"));
        assert_eq!(
            message,
            "the section `agents` is not valid: the key `goal` must not be empty"
        );
        let message = config_message(&with("[agents.limits]\nmax_concurrency = 0\n"));
        assert_eq!(
            message,
            "the section `agents` is not valid: limits.max_concurrency must be larger than 0"
        );
        let message = config_message(&with("[response]\nplaybooks = \"sometimes\"\n"));
        assert!(
            message.starts_with("the section `response` is not valid:"),
            "{message}"
        );
        let message = config_message(&with("[response]\nexecution_timeout_seconds = 0\n"));
        assert_eq!(
            message,
            "the section `response` is not valid: the key `execution_timeout_seconds` must be \
             larger than 0"
        );
    }

    #[test]
    fn the_audit_section_checks_its_kind_against_the_storage() {
        let no_path = MINIMAL.replace("path = \"data/audit.jsonl\"", "kind = \"file\"");
        assert_eq!(
            config_message(&no_path),
            "the section `audit` is not valid: kind = \"file\" needs the key `path`"
        );
        let in_memory = MINIMAL.replace("path = \"data/audit.jsonl\"", "kind = \"postgres\"");
        assert_eq!(
            config_message(&in_memory),
            "the section `audit` is not valid: kind = \"postgres\" needs storage.kind = \
             \"postgres\""
        );
        let both = MINIMAL.replace(
            "path = \"data/audit.jsonl\"",
            "kind = \"postgres\"\npath = \"data/audit.jsonl\"",
        );
        assert_eq!(
            config_message(&both),
            "the section `audit` is not valid: kind = \"postgres\" does not use the key `path`"
        );
    }

    #[test]
    fn the_detection_runner_cannot_share_a_durable_name_with_the_agents() {
        let message = config_message(&MINIMAL.replace(
            "pack = \"detections/aegis-identity\"",
            "pack = \"detections/aegis-identity\"\n\n[detection.runner]\ndurable_name = \
             \"aegis-agents-incidents\"",
        ));
        assert!(
            message.starts_with(
                "the section `detection` is not valid: runner.durable_name is \
                 `aegis-agents-incidents`"
            ),
            "{message}"
        );
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn the_postgres_storage_reads_the_storage_configuration_and_hides_the_url() {
        let text = MINIMAL
            .replace(
                "[storage]\n        kind = \"memory\"",
                "[storage]\nkind = \"postgres\"\nurl = \"postgres://aegis:hunter2secret@db.example/aegis\"\nmax_connections = 3",
            )
            .replace("path = \"data/audit.jsonl\"", "kind = \"postgres\"");
        let settings = read(&text).unwrap();
        assert_eq!(settings.storage.kind(), "postgres");
        assert!(matches!(settings.audit, AuditSettings::Postgres));
        let StorageSettings::Postgres(storage) = &settings.storage else {
            panic!("the storage must be PostgreSQL");
        };
        assert_eq!(storage.max_connections, 3);

        // A value of the section is not in the error for a key that is not valid.
        let broken = text.replace("max_connections = 3", "max_connections = \"many\"");
        let message = config_message(&broken);
        assert!(
            message.starts_with("the section `storage` is not valid:"),
            "{message}"
        );
        assert!(!message.contains("hunter2secret"), "{message}");
    }

    #[cfg(not(feature = "postgres"))]
    #[test]
    fn the_postgres_storage_needs_its_cargo_feature() {
        let text = MINIMAL.replace(
            "[storage]\n        kind = \"memory\"",
            "[storage]\nkind = \"postgres\"\nurl = \"postgres://db.example/aegis\"",
        );
        assert_eq!(
            config_message(&text),
            "the section `storage` is not valid: kind = \"postgres\" needs the Cargo feature \
             `postgres`, and this build does not have it"
        );
    }

    #[cfg(not(feature = "plugins"))]
    #[test]
    fn the_plugins_section_needs_its_cargo_feature() {
        assert_eq!(
            config_message(&with("[plugins]\ndir = \"plugins\"\n")),
            "the section `plugins` is not valid: the section needs the Cargo feature \
             `plugins`, and this build does not have it"
        );
    }

    #[cfg(feature = "plugins")]
    #[test]
    fn the_plugins_section_reads_the_directory_and_the_limits() {
        let settings = read(&with(
            "[plugins]\ndir = \"plugins\"\n\n[plugins.limits]\nrequire_sha256 = true\n\
             call_timeout_seconds = 5\n",
        ))
        .unwrap();
        let plugins = settings.plugins.unwrap();
        assert_eq!(plugins.dir, PathBuf::from("/etc/aegis/plugins"));
        assert_eq!(plugins.limits.require_sha256, Some(true));
        assert_eq!(plugins.limits.call_timeout_seconds, Some(5));
        assert_eq!(plugins.limits.max_memory_bytes, None);
    }

    #[test]
    fn section_error_keeps_the_variant_and_names_the_section() {
        let error = section_error("bus", Error::Unavailable("no server answers".to_owned()));
        assert!(
            matches!(&error, Error::Unavailable(message) if message == "[bus] no server answers"),
            "{error:?}"
        );
        assert!(error.is_retryable());
        let error = section_error("policy", Error::Config("policy file x: no rule".to_owned()));
        assert!(
            matches!(&error, Error::Config(message)
                if message == "the section `policy` is not valid: policy file x: no rule"),
            "{error:?}"
        );
        let error = section_error(
            "policy",
            Error::Config("the section `policy` is not valid: key `paths`".to_owned()),
        );
        assert!(
            matches!(&error, Error::Config(message)
                if message == "the section `policy` is not valid: key `paths`"),
            "{error:?}"
        );
    }
}
