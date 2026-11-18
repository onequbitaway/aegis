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
//! | `response` | `dry_run`, `playbooks`, `playbook_dir`, `graph`, `webhook`, `routes`, `revert` | No |
//! | `sources` | A list of [`SourceConfig`] | No |
//! | `ingest` | `checkpoint_dir` and `retry` | No |
//! | `plugins` | `dir` and `limits` | No |
//! | `decoy` | `aegis_decoy::DecoyConfig` | No |
//! | `evidence` | `enabled`, `path`, and `max_bytes` | No |
//! | `share` | [`ShareSettings`] | Only for the sharing commands |
//! | `api` | `aegis_api::ApiConfig` | Only with the module `api` |
//!
//! A section name that is not in this table is an error. Each section rejects a key that
//! it does not know.
//!
//! # The operator API
//!
//! The module `api` in the module set starts the operator API. It needs the Cargo feature
//! `api`, the `[api]` section, and one enabled agent or more.
//! [`Settings::check_api_module`] checks these rules.
//!
//! # The decoy service
//!
//! The `[decoy]` section starts one decoy service when the module `ingest` is in the
//! module set. It needs the Cargo feature `decoy`. The decoy address must not be the
//! address of the operator API.
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
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The names of the sections that the composition root reads.
pub const SECTIONS: [&str; 19] = [
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
    DECOY_SECTION,
    EVIDENCE_SECTION,
    SHARE_SECTION,
    API_SECTION,
];

/// The name of the section of the operator API.
pub const API_SECTION: &str = "api";

/// The name of the section of the decoy service.
pub const DECOY_SECTION: &str = "decoy";

/// The name of the section of the evidence archive.
pub const EVIDENCE_SECTION: &str = "evidence";

/// The name of the section of the sharing commands.
pub const SHARE_SECTION: &str = "share";

/// The default size limit of the evidence archive: 64 MiB.
pub const DEFAULT_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;

/// The smallest size limit of the evidence archive: 64 KiB.
pub const MIN_EVIDENCE_BYTES: u64 = 64 * 1024;

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
    /// The `[response.revert]` table: the timed revert. `None` means that the timed
    /// revert is off. The dispatcher then refuses a request with a revert time that is
    /// not a dry run.
    pub revert: Option<RevertSettings>,
}

/// The `[response.revert]` table: the store and the timing of the timed reverts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertSettings {
    /// The file that holds the pending reverts. One process uses one file.
    pub store: PathBuf,
    /// The delay after the first revert attempt that fails, in seconds.
    pub retry_base_seconds: u64,
    /// The longest delay between two revert attempts, in seconds.
    pub retry_max_seconds: u64,
    /// The time between two examinations of an approval that a revert waits for, in
    /// seconds.
    pub approval_poll_seconds: u64,
}

/// The `[evidence]` section: the archive of the detections and their events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSettings {
    /// The archive file, as JSON Lines.
    pub path: PathBuf,
    /// The largest number of bytes that the archive keeps on the disk.
    pub max_bytes: u64,
}

/// One hosting network of the `[share]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareNetwork {
    /// The addresses of the network in CIDR form, for example `203.0.113.0/24`.
    pub prefix: IpNet,
    /// The name of the network or of its operator.
    pub name: String,
    /// The abuse contact of the network.
    #[serde(default)]
    pub abuse_contact: Option<String>,
}

/// The organization that sends a report, from the `[share]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareReporter {
    /// The name that the receiver sees.
    pub name: String,
    /// How the receiver can reply, for example a mailbox.
    #[serde(default)]
    pub contact: Option<String>,
}

/// The `[share]` section: the rules of the sharing commands.
///
/// The sharing commands write documents that the operator can send to other defenders.
/// They refuse to run with no `operator_networks`, because an address of the operator
/// must not be in such a document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareSettings {
    /// The address rules. `operator_networks` holds all public networks of the operator.
    pub addresses: aegis_share::AddressPolicy,
    /// The domains of the operator. An export never gives them or their subdomains.
    pub operator_domains: Vec<String>,
    /// The organization that sends a report. With `None`, a report names no reporter.
    pub reporter: Option<ShareReporter>,
    /// The hosting networks that the operator knows. A report package then has one more
    /// report for each of these networks.
    pub networks: Vec<ShareNetwork>,
}

impl ShareSettings {
    /// Returns `true` if the section names one operator network or more.
    #[must_use]
    pub fn has_operator_networks(&self) -> bool {
        !self.addresses.operator_networks.is_empty()
    }
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
    /// The `[decoy]` section: the decoy service. `None` means that the process has no
    /// decoy.
    #[cfg(feature = "decoy")]
    pub decoy: Option<aegis_decoy::DecoyConfig>,
    /// The `[evidence]` section. `None` means that the archive is off.
    pub evidence: Option<EvidenceSettings>,
    /// The `[share]` section.
    pub share: ShareSettings,
    /// The `[api]` section: the operator API.
    ///
    /// `None` means that the document has no `[api]` section, or that a different
    /// component of the process reads the section.
    #[cfg(feature = "api")]
    pub api: Option<aegis_api::ApiConfig>,
}

/// The value of the `[api]` section in this build.
#[cfg(feature = "api")]
type ApiSection = Option<aegis_api::ApiConfig>;

/// A build without the Cargo feature `api` keeps no value of the `[api]` section.
#[cfg(not(feature = "api"))]
type ApiSection = ();

/// The value of the `[decoy]` section in this build.
#[cfg(feature = "decoy")]
type DecoySection = Option<aegis_decoy::DecoyConfig>;

/// A build without the Cargo feature `decoy` keeps no value of the `[decoy]` section.
#[cfg(not(feature = "decoy"))]
type DecoySection = ();

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
    revert: Option<RevertSection>,
}

/// The `[response.revert]` table.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RevertSection {
    enabled: bool,
    store: Option<PathBuf>,
    retry_base_seconds: u64,
    retry_max_seconds: u64,
    approval_poll_seconds: u64,
}

impl Default for RevertSection {
    fn default() -> Self {
        let scheduler = aegis_respond::RevertSchedulerConfig::default();
        Self {
            enabled: true,
            store: None,
            retry_base_seconds: scheduler.retry_base.as_secs(),
            retry_max_seconds: scheduler.retry_max.as_secs(),
            approval_poll_seconds: scheduler.approval_poll.as_secs(),
        }
    }
}

/// The `[evidence]` section.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EvidenceSection {
    enabled: bool,
    path: Option<PathBuf>,
    max_bytes: u64,
}

impl Default for EvidenceSection {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
            max_bytes: DEFAULT_EVIDENCE_BYTES,
        }
    }
}

/// The `[share]` section.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ShareSection {
    operator_networks: Vec<IpNet>,
    operator_domains: Vec<String>,
    permit_documentation_ranges: bool,
    reporter: Option<ShareReporter>,
    networks: Vec<ShareNetwork>,
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
            revert: None,
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

/// Returns `true` if two listeners of one host cannot both open.
///
/// The two addresses have the same port, and they have the same address or one of them
/// covers all interfaces. With the port 0, the operating system selects a free port, so
/// such a listener never has the port of a different listener.
#[cfg(all(feature = "decoy", feature = "api"))]
fn same_listener(first: std::net::SocketAddr, second: std::net::SocketAddr) -> bool {
    if first.port() == 0 || second.port() == 0 {
        return false;
    }
    first.port() == second.port()
        && (first.ip() == second.ip()
            || first.ip().is_unspecified()
            || second.ip().is_unspecified())
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
        let decoy = take(Self::decoy(config), &mut problems);
        let evidence = take(Self::evidence(config, base_dir), &mut problems);
        let share = take(Self::share(config), &mut problems);
        let api = take(Self::api(config, extra_sections), &mut problems);
        #[cfg(feature = "decoy")]
        if let (Some(Some(decoy)), Some(sources)) = (&decoy, &sources)
            && let Err(error) = Self::decoy_name(decoy, sources)
        {
            problems.push(error);
        }
        #[cfg(all(feature = "decoy", feature = "api"))]
        if let (Some(Some(decoy)), Some(Some(api))) = (&decoy, &api)
            && let Err(error) = Self::decoy_address(decoy, api)
        {
            problems.push(error);
        }
        #[cfg(feature = "api")]
        if let (Some(Some(api)), Some(agents), Some(detection)) = (&api, &agents, &detection)
            && let Err(error) = Self::api_durable_names(api, agents, &detection.runner)
        {
            problems.push(error);
        }

        if !problems.is_empty() {
            return Err(problems);
        }
        let settings = (|| {
            // A build without the Cargo feature `api` keeps no value of the section.
            #[cfg(not(feature = "api"))]
            api?;
            #[cfg(not(feature = "decoy"))]
            decoy?;
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
                #[cfg(feature = "decoy")]
                decoy: decoy?,
                evidence: evidence?,
                share: share?,
                #[cfg(feature = "api")]
                api: api?,
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
        // The limit on the states of one incident applies in the service and in a replay.
        aegis_detect::IncidentCoalescer::new(
            section.runner.max_incident_updates,
            section.runner.incident_update_window_seconds,
        )
        .map_err(|error| config_error("detection", format!("runner: {error}")))?;
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
            revert: Self::revert(section.revert, base_dir)?,
        })
    }

    /// Checks the `[response.revert]` table. A table with `enabled = false` is the same
    /// as no table.
    fn revert(section: Option<RevertSection>, base_dir: &Path) -> Result<Option<RevertSettings>> {
        let Some(section) = section.filter(|section| section.enabled) else {
            return Ok(None);
        };
        let Some(store) = section.store else {
            return Err(config_error(
                "response",
                "revert.enabled needs the key `revert.store`: the file that holds the pending \
                 reverts",
            ));
        };
        if section.retry_base_seconds == 0 || section.approval_poll_seconds == 0 {
            return Err(config_error(
                "response",
                "revert.retry_base_seconds and revert.approval_poll_seconds must be larger \
                 than 0",
            ));
        }
        if section.retry_max_seconds < section.retry_base_seconds {
            return Err(config_error(
                "response",
                "revert.retry_max_seconds must not be less than revert.retry_base_seconds",
            ));
        }
        Ok(Some(RevertSettings {
            store: resolve(base_dir, &store),
            retry_base_seconds: section.retry_base_seconds,
            retry_max_seconds: section.retry_max_seconds,
            approval_poll_seconds: section.approval_poll_seconds,
        }))
    }

    /// Reads the `[evidence]` section. A section with `enabled = false` is the same as no
    /// section.
    fn evidence(config: &Config, base_dir: &Path) -> Result<Option<EvidenceSettings>> {
        if !config.has_section(EVIDENCE_SECTION) {
            return Ok(None);
        }
        let section: EvidenceSection = config.section(EVIDENCE_SECTION)?;
        if !section.enabled {
            return Ok(None);
        }
        let Some(path) = section.path else {
            return Err(config_error(
                EVIDENCE_SECTION,
                "enabled needs the key `path`: the archive file",
            ));
        };
        if section.max_bytes < MIN_EVIDENCE_BYTES {
            return Err(config_error(
                EVIDENCE_SECTION,
                format!("max_bytes must be {MIN_EVIDENCE_BYTES} or more"),
            ));
        }
        Ok(Some(EvidenceSettings {
            path: resolve(base_dir, &path),
            max_bytes: section.max_bytes,
        }))
    }

    /// Reads the `[share]` section.
    fn share(config: &Config) -> Result<ShareSettings> {
        let section: ShareSection = config.section_or_default(SHARE_SECTION)?;
        let addresses = aegis_share::AddressPolicy {
            operator_networks: section.operator_networks,
            permit_documentation_ranges: section.permit_documentation_ranges,
        };
        for (index, domain) in section.operator_domains.iter().enumerate() {
            if domain.trim().is_empty() {
                return Err(config_error(
                    SHARE_SECTION,
                    format!("operator_domains[{index}] is empty"),
                ));
            }
        }
        for (index, network) in section.networks.iter().enumerate() {
            if network.name.trim().is_empty() {
                return Err(config_error(
                    SHARE_SECTION,
                    format!("networks[{index}].name is empty"),
                ));
            }
        }
        if let Some(reporter) = &section.reporter
            && reporter.name.trim().is_empty()
        {
            return Err(config_error(SHARE_SECTION, "reporter.name is empty"));
        }
        Ok(ShareSettings {
            addresses,
            operator_domains: section.operator_domains,
            reporter: section.reporter,
            networks: section.networks,
        })
    }

    /// Reads and checks the `[decoy]` section.
    #[cfg(feature = "decoy")]
    fn decoy(config: &Config) -> Result<DecoySection> {
        if !config.has_section(DECOY_SECTION) {
            return Ok(None);
        }
        let decoy: aegis_decoy::DecoyConfig = config.section(DECOY_SECTION)?;
        decoy
            .validate()
            .map_err(|error| section_error(DECOY_SECTION, error))?;
        Ok(Some(decoy))
    }

    /// Refuses the `[decoy]` section, because this build cannot read it.
    #[cfg(not(feature = "decoy"))]
    fn decoy(config: &Config) -> Result<DecoySection> {
        if config.has_section(DECOY_SECTION) {
            return Err(config_error(
                DECOY_SECTION,
                "the section needs the Cargo feature `decoy`, and this build does not have it",
            ));
        }
        Ok(())
    }

    /// Checks that the decoy and a configured source do not have one connector name.
    ///
    /// The name of a connector is one token of its bus subject. Two connectors with one
    /// name would publish on one subject.
    #[cfg(feature = "decoy")]
    fn decoy_name(decoy: &aegis_decoy::DecoyConfig, sources: &[SourceConfig]) -> Result<()> {
        if sources.iter().any(|source| source.name() == decoy.id) {
            return Err(config_error(
                DECOY_SECTION,
                format!(
                    "id is `{}`, which is the name of a source in `[[sources]]`. Use a \
                     different name",
                    decoy.id
                ),
            ));
        }
        Ok(())
    }

    /// Refuses a decoy on the address of the operator API.
    ///
    /// The decoy is for clients that have no permission. The operator API is for the
    /// operator. One listener cannot be the two, and a decoy that takes the address of the
    /// API stops the API.
    #[cfg(all(feature = "decoy", feature = "api"))]
    fn decoy_address(decoy: &aegis_decoy::DecoyConfig, api: &aegis_api::ApiConfig) -> Result<()> {
        if same_listener(decoy.bind, api.bind) {
            return Err(config_error(
                DECOY_SECTION,
                format!(
                    "bind is {}, which is the address of the operator API (api.bind = {}). A \
                     decoy must not be on the address of the operator API. Use a different \
                     port, and prefer a different network interface",
                    decoy.bind, api.bind
                ),
            ));
        }
        Ok(())
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

    /// Reads and checks the `[api]` section.
    ///
    /// A caller that names `api` in `extra_sections` reads the section itself. The
    /// function then does not examine it.
    #[cfg(feature = "api")]
    fn api(config: &Config, extra_sections: &[String]) -> Result<ApiSection> {
        if !config.has_section(API_SECTION) || extra_sections.iter().any(|name| name == API_SECTION)
        {
            return Ok(None);
        }
        let api: aegis_api::ApiConfig = config.section(API_SECTION)?;
        api.validate()
            .and_then(|()| api.validate_bind())
            .map_err(|error| section_error(API_SECTION, error))?;
        Ok(Some(api))
    }

    /// Checks that the notification task of the API has durable names of its own.
    ///
    /// The task adds `-approvals` and `-incidents` to its name. Two subscribers with one
    /// durable name share the messages, so each one gets only a part of them. The agent
    /// runtime would then not see each incident.
    #[cfg(feature = "api")]
    fn api_durable_names(
        api: &aegis_api::ApiConfig,
        agents: &AgentSettings,
        runner: &BusRunnerConfig,
    ) -> Result<()> {
        let Some(consumer) = &api.chatops.notifications.durable_consumer else {
            return Ok(());
        };
        let mut taken = vec![runner.durable_name.clone()];
        if let Some(agents) = &agents.runtime.bus_consumer {
            taken.push(format!("{agents}-tasks"));
            taken.push(format!("{agents}-incidents"));
        }
        let wanted = [
            format!("{consumer}-approvals"),
            format!("{consumer}-incidents"),
        ];
        match wanted.iter().find(|name| taken.contains(name)) {
            Some(name) => Err(config_error(
                API_SECTION,
                format!(
                    "chatops.notifications.durable_consumer gives the durable name `{name}`, \
                     which the agent runtime (agents.bus_consumer) or the detection runner \
                     (detection.runner.durable_name) has. Use a different name"
                ),
            )),
            None => Ok(()),
        }
    }

    /// Refuses the `[api]` section, because this build cannot read it.
    ///
    /// A caller that names `api` in `extra_sections` reads the section itself. The
    /// function then does not examine it.
    #[cfg(not(feature = "api"))]
    fn api(config: &Config, extra_sections: &[String]) -> Result<ApiSection> {
        if config.has_section(API_SECTION) && !extra_sections.iter().any(|name| name == API_SECTION)
        {
            return Err(config_error(
                API_SECTION,
                "the section needs the Cargo feature `api`, and this build does not have it",
            ));
        }
        Ok(())
    }

    /// Checks that this build and these settings can run the module `api`.
    ///
    /// The function does nothing if the module `api` is not in the module set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] in these conditions, if the module `api` is in the set:
    ///
    /// - The build does not have the Cargo feature `api`.
    /// - The document has no `[api]` section. The operator API has no default principals
    ///   and no open mode, so the section is necessary.
    /// - No agent is enabled. The operator API shows and drives the agent runtime.
    pub fn check_api_module(&self) -> Result<()> {
        if !self.modules.contains(Module::Api) {
            return Ok(());
        }
        #[cfg(not(feature = "api"))]
        {
            Err(config_error(
                ModuleSet::SECTION,
                "the module `api` needs the Cargo feature `api`, and this build does not have \
                 it. Remove `api` from `enabled`, or use a build with the feature",
            ))
        }
        #[cfg(feature = "api")]
        {
            if self.api.is_none() {
                return Err(api_section_missing());
            }
            if self.agents.runtime.enabled_roles.is_empty() {
                return Err(api_needs_agents());
            }
            Ok(())
        }
    }
}

/// The error for an operator API that has no `[api]` section.
#[cfg(feature = "api")]
pub(crate) fn api_section_missing() -> Error {
    Error::Config(format!(
        "the section `{API_SECTION}` is missing: the operator API needs it. The API has no \
         default principal and no open mode. Add the section, or remove `api` from \
         `modules.enabled`"
    ))
}

/// The error for an operator API in a process that runs no agent.
#[cfg(feature = "api")]
pub(crate) fn api_needs_agents() -> Error {
    config_error(
        ModuleSet::SECTION,
        "the module `api` needs the agent runtime, and no agent is enabled. Enable one agent \
         module or more, for example `monitor`, or remove `api` from `enabled`",
    )
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
    fn the_flood_protection_settings_load_from_the_detection_section() {
        // The defaults of the detection crate.
        let defaults = read(MINIMAL).unwrap().detection;
        assert!(defaults.engine.velocity.machine_cadence.enabled);
        assert_eq!(defaults.engine.velocity.machine_cadence.min_actions, 4);
        assert!(defaults.engine.velocity.endpoint_probe.enabled);
        assert_eq!(defaults.engine.triage.quota_window_seconds, 3600);
        assert_eq!(defaults.engine.triage.max_requests_per_source, 120);
        assert_eq!(defaults.engine.triage.max_requests_per_tenant, 240);
        assert_eq!(defaults.runner.max_incident_updates, 20);
        assert_eq!(defaults.runner.incident_update_window_seconds, 60);

        let text = MINIMAL.to_owned()
            + r#"
            [detection.velocity.machine_cadence]
            min_actions = 6
            max_median_gap_milliseconds = 2000
            ignored_principals = ["sp-provisioning"]
            follow_addresses = false

            [detection.velocity.endpoint_probe]
            distinct_path_threshold = 40
            decoy_paths = ["/.env", "/admin/backup/*"]
            decoy_path_severity = "high"

            [detection.velocity.sign_in_burst]
            failure_threshold = 50

            [detection.triage]
            quota_window_seconds = 600
            max_requests_per_source = 10
            max_requests_per_tenant = 30

            [detection.runner]
            durable_name = "soc-detect"
            max_incident_updates = 5
            incident_update_window_seconds = 120
            "#;
        let detection = read(&text).unwrap().detection;
        let cadence = &detection.engine.velocity.machine_cadence;
        assert_eq!(cadence.min_actions, 6);
        assert_eq!(cadence.max_median_gap_milliseconds, 2000);
        assert_eq!(cadence.ignored_principals, ["sp-provisioning"]);
        assert!(!cadence.follow_addresses);
        // A key that the table does not set keeps its default.
        assert_eq!(cadence.window_seconds, 300);
        let probe = &detection.engine.velocity.endpoint_probe;
        assert_eq!(probe.distinct_path_threshold, 40);
        assert_eq!(probe.decoy_paths, ["/.env", "/admin/backup/*"]);
        assert_eq!(
            probe.decoy_path_severity,
            aegis_contracts::common::Severity::High
        );
        assert_eq!(
            detection.engine.velocity.sign_in_burst.failure_threshold,
            50
        );
        assert_eq!(detection.engine.triage.quota_window_seconds, 600);
        assert_eq!(detection.engine.triage.max_requests_per_source, 10);
        assert_eq!(detection.engine.triage.max_requests_per_tenant, 30);
        assert_eq!(detection.runner.durable_name, "soc-detect");
        assert_eq!(detection.runner.max_incident_updates, 5);
        assert_eq!(detection.runner.incident_update_window_seconds, 120);

        // A limit of zero is an error of the section, before the engine starts.
        for (table, key) in [
            ("runner", "max_incident_updates = 0"),
            ("runner", "incident_update_window_seconds = 0"),
        ] {
            let message = config_message(&format!("{MINIMAL}\n[detection.{table}]\n{key}\n"));
            assert!(
                message.starts_with("the section `detection` is not valid: runner: "),
                "{key}: {message}"
            );
        }
        let message = config_message(&format!(
            "{MINIMAL}\n[detection.velocity.machine_cadence]\nmin_action = 6\n"
        ));
        assert!(
            message.starts_with("the section `detection` is not valid:")
                && message.contains("unknown field"),
            "{message}"
        );
    }

    #[test]
    fn the_revert_table_gives_the_store_and_the_timing() {
        // No table: the timed revert is off.
        assert_eq!(read(MINIMAL).unwrap().response.revert, None);

        let settings = read(&with(
            "[response.revert]\nstore = \"data/pending-reverts.json\"\n",
        ))
        .unwrap();
        assert_eq!(
            settings.response.revert,
            Some(RevertSettings {
                store: PathBuf::from("/etc/aegis/data/pending-reverts.json"),
                retry_base_seconds: 30,
                retry_max_seconds: 1800,
                approval_poll_seconds: 60,
            })
        );
        let settings = read(&with(
            "[response.revert]\nstore = \"/var/lib/aegis/reverts.json\"\nretry_base_seconds = 5\n\
             retry_max_seconds = 50\napproval_poll_seconds = 10\n",
        ))
        .unwrap();
        assert_eq!(
            settings.response.revert,
            Some(RevertSettings {
                store: PathBuf::from("/var/lib/aegis/reverts.json"),
                retry_base_seconds: 5,
                retry_max_seconds: 50,
                approval_poll_seconds: 10,
            })
        );
        // The switch turns the timed revert off, with or without a store.
        for text in [
            "[response.revert]\nenabled = false\n",
            "[response.revert]\nenabled = false\nstore = \"data/pending-reverts.json\"\n",
        ] {
            assert_eq!(read(&with(text)).unwrap().response.revert, None, "{text}");
        }

        for (text, cause) in [
            (
                "[response.revert]\n",
                "revert.enabled needs the key `revert.store`",
            ),
            (
                "[response.revert]\nstore = \"x.json\"\nretry_base_seconds = 0\n",
                "must be larger than 0",
            ),
            (
                "[response.revert]\nstore = \"x.json\"\napproval_poll_seconds = 0\n",
                "must be larger than 0",
            ),
            (
                "[response.revert]\nstore = \"x.json\"\nretry_base_seconds = 60\nretry_max_seconds = 30\n",
                "revert.retry_max_seconds must not be less than revert.retry_base_seconds",
            ),
            ("[response.revert]\nstores = \"x.json\"\n", "unknown field"),
        ] {
            let message = config_message(&with(text));
            assert!(
                message.starts_with("the section `response` is not valid:")
                    && message.contains(cause),
                "{text}: {message}"
            );
        }
    }

    #[test]
    fn the_evidence_section_gives_the_archive_file_and_its_limit() {
        assert_eq!(read(MINIMAL).unwrap().evidence, None);
        let settings = read(&with("[evidence]\npath = \"data/evidence.jsonl\"\n")).unwrap();
        assert_eq!(
            settings.evidence,
            Some(EvidenceSettings {
                path: PathBuf::from("/etc/aegis/data/evidence.jsonl"),
                max_bytes: DEFAULT_EVIDENCE_BYTES,
            })
        );
        let settings = read(&with(
            "[evidence]\npath = \"/var/lib/aegis/evidence.jsonl\"\nmax_bytes = 1048576\n",
        ))
        .unwrap();
        assert_eq!(
            settings.evidence,
            Some(EvidenceSettings {
                path: PathBuf::from("/var/lib/aegis/evidence.jsonl"),
                max_bytes: 1_048_576,
            })
        );
        assert_eq!(
            read(&with("[evidence]\nenabled = false\n"))
                .unwrap()
                .evidence,
            None
        );
        for (text, cause) in [
            ("[evidence]\n", "enabled needs the key `path`"),
            (
                "[evidence]\npath = \"e.jsonl\"\nmax_bytes = 1024\n",
                "max_bytes must be 65536 or more",
            ),
            ("[evidence]\nfile = \"e.jsonl\"\n", "unknown field"),
        ] {
            let message = config_message(&with(text));
            assert!(
                message.starts_with("the section `evidence` is not valid:")
                    && message.contains(cause),
                "{text}: {message}"
            );
        }
    }

    #[test]
    fn the_share_section_gives_the_operator_networks_and_the_receivers() {
        let none = read(MINIMAL).unwrap().share;
        assert_eq!(none, ShareSettings::default());
        assert!(!none.has_operator_networks());

        let share = read(&with(
            r#"
            [share]
            operator_networks = ["198.51.100.0/24", "2001:db8:1::/48"]
            operator_domains = ["operator.example.org"]

            [share.reporter]
            name = "Example Security Team"
            contact = "soc@operator.example.org"

            [[share.networks]]
            prefix = "203.0.113.0/24"
            name = "AS64500 Example Hosting"
            abuse_contact = "abuse@hosting.example"
            "#,
        ))
        .unwrap()
        .share;
        assert!(share.has_operator_networks());
        assert_eq!(
            share.addresses.operator_networks,
            [
                "198.51.100.0/24".parse::<IpNet>().unwrap(),
                "2001:db8:1::/48".parse::<IpNet>().unwrap()
            ]
        );
        assert!(!share.addresses.permit_documentation_ranges);
        assert_eq!(share.operator_domains, ["operator.example.org"]);
        assert_eq!(
            share.reporter,
            Some(ShareReporter {
                name: "Example Security Team".to_owned(),
                contact: Some("soc@operator.example.org".to_owned()),
            })
        );
        assert_eq!(
            share.networks,
            [ShareNetwork {
                prefix: "203.0.113.0/24".parse().unwrap(),
                name: "AS64500 Example Hosting".to_owned(),
                abuse_contact: Some("abuse@hosting.example".to_owned()),
            }]
        );

        for text in [
            "[share]\noperator_networks = [\"198.51.100.0\"]\n",
            "[share]\noperator_networks = [\"not-a-network\"]\n",
            "[share]\noperator_network = [\"198.51.100.0/24\"]\n",
            "[share]\noperator_domains = [\" \"]\n",
            "[share.reporter]\nname = \"\"\n",
            "[[share.networks]]\nprefix = \"203.0.113.0/24\"\nname = \" \"\n",
            "[[share.networks]]\nprefix = \"203.0.113.300/24\"\nname = \"x\"\n",
        ] {
            let message = config_message(&with(text));
            assert!(
                message.starts_with("the section `share` is not valid:"),
                "{text}: {message}"
            );
        }
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

    /// An `[api]` section with one principal.
    const API: &str = "[api]\nbind = \"127.0.0.1:8080\"\n\n[[api.principals]]\n\
        id = \"alice@example.com\"\nroles = [\"approver\"]\ntoken_env = \"AEGIS_TOKEN_ALICE\"\n";

    /// A module set with the module `api` and one agent.
    const API_MODULES: &str =
        "[modules]\nenabled = [\"ingest\", \"detection\", \"monitor\", \"api\"]\n";

    #[cfg(feature = "api")]
    #[test]
    fn the_api_section_is_read_and_each_value_that_is_not_valid_names_the_section() {
        assert!(read(MINIMAL).unwrap().api.is_none());
        let api = read(&with(API)).unwrap().api.unwrap();
        assert_eq!(api.bind.to_string(), "127.0.0.1:8080");
        assert_eq!(api.principals.len(), 1);
        assert_eq!(api.principals[0].id, "alice@example.com");
        assert_eq!(api.principals[0].roles, ["approver"]);
        assert_eq!(
            api.principals[0].token_env.as_deref(),
            Some("AEGIS_TOKEN_ALICE")
        );

        let message = config_message(&with("[api]\nopen = true\n"));
        assert!(
            message.starts_with("the section `api` is not valid:")
                && message.contains("unknown field"),
            "{message}"
        );
        assert_eq!(
            config_message(&with("[api.limits]\nmax_page_size = 5000\n")),
            "the section `api` is not valid: api.limits.max_page_size must be from 1 to 1000"
        );
        assert_eq!(
            config_message(&with(&format!(
                "{API}\n[[api.principals]]\nid = \"alice@example.com\"\n"
            ))),
            "the section `api` is not valid: api.principals[1]: two principals have the same id"
        );

        // The server has no TLS. An address that is not a loopback address needs the
        // explicit switch.
        let message = config_message(&with("[api]\nbind = \"0.0.0.0:8080\"\n"));
        assert!(
            message
                .starts_with("the section `api` is not valid: api.bind is not a loopback address"),
            "{message}"
        );
        let open = read(&with(
            "[api]\nbind = \"0.0.0.0:8080\"\nallow_non_loopback = true\n",
        ))
        .unwrap();
        assert_eq!(open.api.unwrap().bind.to_string(), "0.0.0.0:8080");
    }

    #[cfg(feature = "api")]
    #[test]
    fn the_notification_task_of_the_api_cannot_share_a_durable_name() {
        let with_consumer = |name: &str, extra: &str| {
            with(&format!(
                "{API}\n[api.chatops.notifications]\ndurable_consumer = \"{name}\"\n{extra}"
            ))
        };
        // The default name of the agent runtime is `aegis-agents`.
        assert_eq!(
            config_message(&with_consumer("aegis-agents", "")),
            "the section `api` is not valid: chatops.notifications.durable_consumer gives the \
             durable name `aegis-agents-incidents`, which the agent runtime \
             (agents.bus_consumer) or the detection runner (detection.runner.durable_name) \
             has. Use a different name"
        );
        let text = MINIMAL.replace(
            "pack = \"detections/aegis-identity\"",
            "pack = \"detections/aegis-identity\"\n\n[detection.runner]\n\
             durable_name = \"soc-approvals\"",
        ) + "\n"
            + API
            + "\n[api.chatops.notifications]\ndurable_consumer = \"soc\"\n";
        let message = config_message(&text);
        assert!(
            message.starts_with(
                "the section `api` is not valid: chatops.notifications.durable_consumer gives \
                 the durable name `soc-approvals`"
            ),
            "{message}"
        );

        // A name of its own is valid, and so is the name of the agents when the agents use
        // a different one.
        let own = read(&with_consumer("aegis-chat", "")).unwrap();
        assert_eq!(
            own.api
                .unwrap()
                .chatops
                .notifications
                .durable_consumer
                .as_deref(),
            Some("aegis-chat")
        );
        assert!(
            read(&with_consumer(
                "aegis-agents",
                "\n[agents]\nbus_consumer = \"soc-agents\"\n"
            ))
            .is_ok()
        );
    }

    #[cfg(not(feature = "api"))]
    #[test]
    fn the_api_section_needs_its_cargo_feature() {
        assert_eq!(
            config_message(&with(API)),
            "the section `api` is not valid: the section needs the Cargo feature `api`, and \
             this build does not have it"
        );
    }

    #[test]
    fn a_component_that_reads_the_api_section_itself_keeps_it_from_the_settings() {
        // The table has a key that the API configuration does not know.
        let text = with(&format!(
            "{API_MODULES}\n[api]\nlisten = \"127.0.0.1:8080\"\n"
        ));
        let config = Config::from_toml_str(&text).unwrap();
        let base = Path::new("/etc/aegis");
        assert!(matches!(
            Settings::from_config(&config, base, &[]),
            Err(Error::Config(message)) if message.starts_with("the section `api` is not valid:")
        ));

        let settings = Settings::from_config(&config, base, &["api".to_owned()]).unwrap();

        assert!(settings.modules.contains(Module::Api));
        #[cfg(feature = "api")]
        assert!(settings.api.is_none());
    }

    #[cfg(feature = "api")]
    #[test]
    fn the_module_api_needs_the_api_section_and_an_agent() {
        let message = |text: &str| match read(text).unwrap().check_api_module() {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, found {other:?}"),
        };
        // The module is not in the set: the section is optional.
        assert!(read(MINIMAL).unwrap().check_api_module().is_ok());
        assert!(read(&with(API)).unwrap().check_api_module().is_ok());

        assert!(
            read(&with(&format!("{API_MODULES}\n{API}")))
                .unwrap()
                .check_api_module()
                .is_ok()
        );
        assert_eq!(
            message(&with(API_MODULES)),
            "the section `api` is missing: the operator API needs it. The API has no default \
             principal and no open mode. Add the section, or remove `api` from \
             `modules.enabled`"
        );
        assert_eq!(
            message(&with(&format!(
                "[modules]\nenabled = [\"ingest\", \"detection\", \"api\"]\n\n{API}"
            ))),
            "the section `modules` is not valid: the module `api` needs the agent runtime, and \
             no agent is enabled. Enable one agent module or more, for example `monitor`, or \
             remove `api` from `enabled`"
        );
        // The operator removed each agent role: the process runs no agent.
        assert!(
            message(&with(&format!(
                "{API_MODULES}\n{API}\n[agents]\nenabled_roles = []\n"
            )))
            .starts_with("the section `modules` is not valid: the module `api` needs the agent")
        );
    }

    #[cfg(not(feature = "api"))]
    #[test]
    fn the_module_api_needs_its_cargo_feature() {
        assert!(read(MINIMAL).unwrap().check_api_module().is_ok());
        let error = read(&with(API_MODULES))
            .unwrap()
            .check_api_module()
            .unwrap_err();
        assert!(
            matches!(&error, Error::Config(message)
                if message == "the section `modules` is not valid: the module `api` needs the \
                    Cargo feature `api`, and this build does not have it. Remove `api` from \
                    `enabled`, or use a build with the feature"),
            "{error:?}"
        );
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
