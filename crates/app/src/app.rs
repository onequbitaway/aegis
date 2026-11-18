//! The application: all subsystems of one AEGIS process, built from one configuration.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aegis_agents::{AgentRuntime, BUILT_IN_ROLES, RunReport};
use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionOutcome, ActionStatus,
};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::bus::{MessageBus, publish_json, subject};
use aegis_contracts::common::{ApprovalId, IncidentId, TaskId};
use aegis_contracts::event::Event;
use aegis_contracts::graph::{DefensiveGraph, VectorStore};
use aegis_contracts::incident::IncidentStore;
use aegis_contracts::model::ModelProvider;
use aegis_contracts::policy::{
    ApprovalQueue, ApprovalRequest, PolicyDecision, PolicyEffect, Principal, PrincipalKind,
};
use aegis_contracts::source::SourceConnector;
use aegis_contracts::{AgentContext, AgentInput, AgentRole, AgentTask, Error, Result};
use aegis_core::{Config, Module, ModuleSet, Shutdown};
use aegis_detect::{DetectionEngine, RulePack};
use aegis_ingest::{
    CheckpointStore, FileCheckpointStore, IngestStats, MemoryCheckpointStore, RunOutcome,
    SourceRegistry,
};
use aegis_memory::{MemoryApprovals, MemoryGraph, MemoryIncidents, MemoryVectors};
use aegis_policy::{ApprovalService, FileAuditLog, Permission, Rbac, RegoPolicyEngine};
use aegis_respond::{
    ActionRegistry, Dispatcher, GraphActionConnector, HoneytokenConnector, HoneytokenRegistry,
    HoneytokenTripDetector, MemoryHoneytokenStore, MemorySecretSink, WebhookConnector,
};
use chrono::Utc;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::actions::{ActionJournal, DispatchResult, SimulationConnector};
use crate::activity::Activity;
use crate::audit::PublishingAuditLog;
use crate::bridge::{AgentFeed, Bridge, DetectionBus, IngestTap, Progress};
use crate::incidents::SharedIncidents;
use crate::offline::OfflineModel;
use crate::playbooks::Playbooks;
use crate::report::{
    ApprovalOutcome, AuditSummary, ReloadReport, ReplayReport, RunSummary, SourceSummary,
};
use crate::settings::{AuditSettings, PlaybookMode, Settings, StorageSettings, section_error};

/// The audit actor of the records that the composition root writes for its own steps.
pub const APP_ACTOR: &str = "aegis";

/// The policy name in the decision that an agent gets when a person rejects an approval.
pub const APPROVAL_REJECTED_POLICY: &str = "aegis.approval.rejected";

/// The name of the honeytoken connector in the action registry.
pub const HONEYTOKEN_CONNECTOR: &str = "honeytokens";

type ServiceFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// One more long-running component that [`App::run_with`] starts, for example the
/// operator API.
///
/// The component gets a [`Shutdown`]. It must return when the signal is triggered. If the
/// component returns an error, the application stops all components.
///
/// With the Cargo feature `api`, the function `api::service` of this crate makes the
/// service of the operator API.
pub struct Service {
    name: String,
    module: Option<Module>,
    start: Box<dyn FnOnce(Shutdown) -> ServiceFuture + Send>,
}

impl Service {
    /// Makes a service. `start` gets the shutdown signal and returns the work.
    pub fn new<F, Fut>(name: impl Into<String>, start: F) -> Self
    where
        F: FnOnce(Shutdown) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        Self {
            name: name.into(),
            module: None,
            start: Box::new(move |shutdown| Box::pin(start(shutdown))),
        }
    }

    /// Sets the module that this service implements. [`App::run_with`] starts the service
    /// only if the module is in the module set.
    #[must_use]
    pub fn for_module(mut self, module: Module) -> Self {
        self.module = Some(module);
        self
    }
}

/// The options of [`App::run_with`].
#[derive(Default)]
pub struct RunOptions {
    /// With `true`, the run stops when all sources are at their end and the detection
    /// engine completed their events. Use this for a session on recorded events.
    pub stop_when_sources_end: bool,
    /// More components to run with the application.
    pub services: Vec<Service>,
}

/// Makes an [`App`] with options that the configuration file does not have.
pub struct AppBuilder<'a> {
    config: &'a Config,
    base_dir: Option<PathBuf>,
    extra_sections: Vec<String>,
    modules: Option<ModuleSet>,
    model: Option<Arc<dyn ModelProvider>>,
    action_connectors: Vec<Arc<dyn ActionConnector>>,
    sources: Vec<Arc<dyn SourceConnector>>,
    use_configured_sources: bool,
    audit_file: Option<PathBuf>,
    local_session: bool,
    force_dry_run: bool,
}

impl AppBuilder<'_> {
    /// Sets the directory that relative paths of the configuration start at. The default
    /// is the working directory of the process.
    #[must_use]
    pub fn base_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.base_dir = Some(directory.into());
        self
    }

    /// Permits a section that a different component of the process reads. A section that
    /// no component reads is an error.
    ///
    /// With the name `api`, the application does not read the `[api]` section. The caller
    /// then supplies the operator API for the module `api`.
    #[must_use]
    pub fn allow_section(mut self, name: impl Into<String>) -> Self {
        self.extra_sections.push(name.into());
        self
    }

    /// Replaces the module set of the configuration.
    #[must_use]
    pub fn modules(mut self, modules: ModuleSet) -> Self {
        self.modules = Some(modules);
        self
    }

    /// Replaces the model of the configuration with `model`.
    #[must_use]
    pub fn model(mut self, model: Arc<dyn ModelProvider>) -> Self {
        self.model = Some(model);
        self
    }

    /// Adds an action connector. It has priority over the connectors of the configuration
    /// for the action types that it supports.
    #[must_use]
    pub fn action_connector(mut self, connector: Arc<dyn ActionConnector>) -> Self {
        self.action_connectors.push(connector);
        self
    }

    /// Adds a source connector.
    #[must_use]
    pub fn source(mut self, source: Arc<dyn SourceConnector>) -> Self {
        self.sources.push(source);
        self
    }

    /// Ignores the `[[sources]]` of the configuration. Only the sources of
    /// [`AppBuilder::source`] and of the plugins remain.
    #[must_use]
    pub fn without_configured_sources(mut self) -> Self {
        self.use_configured_sources = false;
        self
    }

    /// Makes the application a local session that does not touch the systems of the
    /// configuration.
    ///
    /// The session uses the in-process bus and the in-memory storage in place of the bus
    /// and the storage of the configuration. It writes its audit log to `audit_file`, and
    /// it keeps the cursors of the sources in memory. All other settings stay: the rule
    /// pack, the policy, the playbooks, the agents, and the model.
    #[must_use]
    pub fn local_session(mut self, audit_file: impl Into<PathBuf>) -> Self {
        self.local_session = true;
        self.audit_file(audit_file)
    }

    /// Makes each action a dry run, also when the configuration permits changes.
    ///
    /// The dispatcher and the agents get their dry-run switches, and a playbook mode of
    /// `live` becomes `dry_run`. Use this to examine recorded events with a configuration
    /// that is live.
    #[must_use]
    pub fn force_dry_run(mut self) -> Self {
        self.force_dry_run = true;
        self
    }

    /// Writes the audit log to the file `audit_file`, in place of the audit log of the
    /// configuration. A relative path starts at the base directory.
    ///
    /// One process writes one audit file. Use this for a second application on a host
    /// where a service holds the audit file of the configuration.
    #[must_use]
    pub fn audit_file(mut self, audit_file: impl Into<PathBuf>) -> Self {
        self.audit_file = Some(audit_file.into());
        self
    }

    /// Builds all subsystems.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`App::build`].
    pub async fn build(self) -> Result<App> {
        let base_dir = match self.base_dir {
            Some(directory) => directory,
            None => std::env::current_dir().map_err(|error| {
                Error::Config(format!("cannot read the working directory: {error}"))
            })?,
        };
        let mut settings = match self.modules {
            Some(modules) => Settings::from_config_with_modules(
                self.config,
                &base_dir,
                &self.extra_sections,
                modules,
            )?,
            None => Settings::from_config(self.config, &base_dir, &self.extra_sections)?,
        };
        if !self.use_configured_sources {
            settings.sources.clear();
        }
        if self.force_dry_run {
            settings.response.dry_run = true;
            settings.agents.runtime.dry_run = true;
            if settings.response.playbooks == PlaybookMode::Live {
                settings.response.playbooks = PlaybookMode::DryRun;
            }
        }
        if self.local_session {
            settings.bus.kind = aegis_bus::BusKind::Memory;
            settings.storage = StorageSettings::Memory;
            settings.ingest.checkpoint_dir = None;
        }
        if let Some(audit_file) = self.audit_file {
            settings.audit = AuditSettings::File(aegis_policy::FileAuditLogConfig {
                path: if audit_file.is_absolute() {
                    audit_file
                } else {
                    base_dir.join(audit_file)
                },
            });
        }
        App::assemble(settings, self.model, self.action_connectors, self.sources).await
    }
}

/// The storage services of one process.
struct Stores {
    graph: Arc<dyn DefensiveGraph>,
    vectors: Arc<dyn VectorStore>,
    incidents: Arc<dyn IncidentStore>,
    approvals: Arc<dyn ApprovalQueue>,
    audit: Arc<dyn AuditLog>,
    #[cfg(feature = "postgres")]
    postgres: Option<aegis_storage::PgStore>,
}

/// The connectors that the plugins of the operator supply.
#[derive(Default)]
struct Plugins {
    sources: Vec<Arc<dyn SourceConnector>>,
    actions: Vec<Arc<dyn ActionConnector>>,
}

/// All subsystems of one AEGIS process.
///
/// Make the value with [`App::build`] or [`App::builder`]. Then use one of the two run
/// modes:
///
/// - [`App::run`] is the service. It runs until the shutdown signal.
/// - [`App::replay`] examines a list of events in the process and returns a report.
///
/// The accessors give the services to other components, for example an operator API.
pub struct App {
    settings: Settings,
    activity: Arc<Activity>,
    bus: Arc<dyn MessageBus>,
    graph: Arc<dyn DefensiveGraph>,
    vectors: Arc<dyn VectorStore>,
    incidents: Arc<SharedIncidents>,
    approvals: Arc<dyn ApprovalQueue>,
    audit: Arc<PublishingAuditLog>,
    models: Arc<dyn ModelProvider>,
    has_model: bool,
    policy: Arc<RegoPolicyEngine>,
    rbac: Arc<Rbac>,
    approval_service: Arc<ApprovalService>,
    action_registry: Arc<ActionRegistry>,
    dispatcher: Arc<Dispatcher>,
    actions: Arc<ActionJournal>,
    playbooks: Arc<Playbooks>,
    engine: Arc<DetectionEngine>,
    agents: Option<Arc<AgentRuntime>>,
    sources: Arc<SourceRegistry>,
    checkpoints: Arc<dyn CheckpointStore>,
    honeytokens: Arc<HoneytokenRegistry>,
    rotated_secrets: Arc<MemorySecretSink>,
    bridge: Arc<Bridge>,
    /// Held by [`App::run_with`] and [`App::replay`]: one of them at a time.
    exclusive: tokio::sync::Mutex<()>,
    service_runs: AtomicBool,
    start_recorded: AtomicBool,
    #[cfg(feature = "postgres")]
    postgres: Option<aegis_storage::PgStore>,
}

/// The state after the approval service recorded the decision of a person.
pub(crate) struct Decided {
    /// The approval request with the decision.
    pub(crate) approval: ApprovalRequest,
    /// For an approval: what the dispatcher did with the action. If the action did not
    /// run, this is the failed outcome that the agent got. For a rejection: `None`.
    pub(crate) disposition: Option<ActionDisposition>,
    /// The error of a step after the record of the decision: the action did not run, or
    /// the agent did not get the result.
    pub(crate) failure: Option<Error>,
}

/// Sets the "service runs" flag back when [`App::run_with`] returns.
struct ServiceFlag<'a>(&'a AtomicBool);

impl Drop for ServiceFlag<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// How one component of a service run ended.
enum TaskEnd {
    Ingest {
        name: String,
        result: Result<RunOutcome>,
        stats: IngestStats,
    },
    Detection(Result<aegis_detect::RunSummary>),
    Agents(Result<RunReport>),
    Service {
        name: String,
        result: Result<()>,
    },
    Helper,
}

fn add_reports(total: &mut RunReport, part: &RunReport) {
    total.tasks_completed += part.tasks_completed;
    total.tasks_failed += part.tasks_failed;
    total.tasks_rejected += part.tasks_rejected;
    total.actions_dispatched += part.actions_dispatched;
    total.actions_rejected += part.actions_rejected;
    total.dispatch_failures += part.dispatch_failures;
    total.audit_failures += part.audit_failures;
}

/// Returns the agent role of a principal that an agent runtime made.
fn agent_role(principal: &Principal) -> Option<AgentRole> {
    if principal.kind != PrincipalKind::Agent {
        return None;
    }
    Some(
        BUILT_IN_ROLES
            .iter()
            .find(|role| role.token() == principal.id)
            .cloned()
            .unwrap_or_else(|| AgentRole::Custom(principal.id.clone())),
    )
}

impl App {
    /// Builds all subsystems from `config`.
    ///
    /// A relative path in the configuration starts at the working directory of the
    /// process. Use [`App::builder`] to set a different directory.
    ///
    /// The function connects to the bus and to the database, runs the database
    /// migrations, opens the audit log, and loads the rule pack, the policy, the
    /// playbooks, and the plugins. It starts no long-running work.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a section is missing or not valid. The message names
    /// the section. Returns the error of a subsystem that cannot start, for example
    /// [`Error::Unavailable`] if the bus does not answer. No error message contains a
    /// secret.
    pub async fn build(config: &Config) -> Result<Self> {
        Self::builder(config).build().await
    }

    /// Starts a builder for options that the configuration file does not have.
    #[must_use]
    pub fn builder(config: &Config) -> AppBuilder<'_> {
        AppBuilder {
            config,
            base_dir: None,
            extra_sections: Vec::new(),
            modules: None,
            model: None,
            action_connectors: Vec::new(),
            sources: Vec::new(),
            use_configured_sources: true,
            audit_file: None,
            local_session: false,
            force_dry_run: false,
        }
    }

    async fn assemble(
        settings: Settings,
        model: Option<Arc<dyn ModelProvider>>,
        extra_actions: Vec<Arc<dyn ActionConnector>>,
        extra_sources: Vec<Arc<dyn SourceConnector>>,
    ) -> Result<Self> {
        let activity = Arc::new(Activity::new());
        let bus = aegis_bus::connect(&settings.bus)
            .await
            .map_err(|error| section_error("bus", error))?;
        let stores = Self::stores(&settings).await?;
        let audit = Arc::new(PublishingAuditLog::new(
            stores.audit.clone(),
            bus.clone(),
            activity.clone(),
        ));

        let (models, has_model): (Arc<dyn ModelProvider>, bool) = match (model, &settings.model) {
            (Some(model), _) => (model, true),
            (None, Some(config)) => {
                let router = aegis_model::build_router(config, aegis_model::process_env)
                    .map_err(|error| section_error("model", error))?;
                (Arc::new(router), true)
            }
            (None, None) => (Arc::new(OfflineModel), false),
        };

        let honeytokens =
            Arc::new(HoneytokenRegistry::open(Arc::new(MemoryHoneytokenStore::default())).await?);
        let plugins = Self::plugins(&settings).await?;

        // Detection: the rule pack, tier 2 if the process has a model, and the detector
        // for the honeytokens of the registry.
        let pack_dir = settings.detection.pack.clone();
        let pack = tokio::task::spawn_blocking(move || RulePack::load(pack_dir))
            .await
            .map_err(|error| Error::other("load the rule pack", error))?
            .map_err(|error| section_error("detection", error.into()))?;
        let mut engine = DetectionEngine::new(settings.detection.engine.clone(), pack)
            .map_err(|error| section_error("detection", error.into()))?;
        if has_model {
            engine = engine
                .with_triage(models.clone())
                .map_err(|error| section_error("detection", error.into()))?;
        }
        let engine = Arc::new(
            engine.with_detector(Arc::new(HoneytokenTripDetector::new(honeytokens.clone()))),
        );

        // The playbook set is made after the dispatcher. The incident store must tell it
        // when an incident closes, so the hook reads it from this cell. The cell holds a
        // weak reference: the playbook set holds the dispatcher, and the dispatcher holds
        // the incident store.
        let playbook_cell: Arc<std::sync::OnceLock<std::sync::Weak<Playbooks>>> = Arc::default();
        let incidents = Arc::new(
            SharedIncidents::new(stores.incidents.clone(), activity.clone())
                .on_closed({
                    let engine = engine.clone();
                    move |id| {
                        engine.forget_incident(id);
                    }
                })
                .on_closed({
                    let playbooks = playbook_cell.clone();
                    move |id| {
                        if let Some(playbooks) = playbooks.get().and_then(std::sync::Weak::upgrade)
                        {
                            playbooks.forget(id);
                        }
                    }
                }),
        );

        let policy = Arc::new(
            RegoPolicyEngine::from_config(&settings.policy)
                .map_err(|error| section_error("policy", error))?,
        );
        let rbac = Arc::new(Rbac::new(settings.rbac.clone()));
        let audit_log: Arc<dyn AuditLog> = audit.clone();
        let approval_service = Arc::new(
            ApprovalService::new(stores.approvals.clone(), rbac.clone(), audit_log.clone())
                .with_rules(settings.approval),
        );

        let rotated_secrets = Arc::new(MemorySecretSink::default());
        let action_registry = Arc::new(Self::build_action_registry(
            &settings,
            extra_actions,
            plugins.actions,
            &honeytokens,
            &rotated_secrets,
        )?);
        let shared_incidents: Arc<dyn IncidentStore> = incidents.clone();
        let dispatcher = Arc::new(
            Dispatcher::builder(
                action_registry.clone(),
                policy.clone(),
                stores.approvals.clone(),
                audit_log.clone(),
            )
            .incidents(shared_incidents.clone())
            .bus(bus.clone())
            .environment(settings.response.environment.clone())
            .dry_run(settings.response.dry_run)
            .execution_timeout(Duration::from_secs(
                settings.response.execution_timeout_seconds,
            ))
            .build(),
        );
        let actions = Arc::new(ActionJournal::new(dispatcher.clone(), activity.clone()));
        let action_dispatcher: Arc<dyn ActionDispatcher> = actions.clone();

        let playbooks = Arc::new(
            Playbooks::load(
                action_dispatcher.clone(),
                settings.response.playbook_dir.clone(),
                settings.response.playbooks,
            )
            .await
            .map_err(|error| section_error("response", error))?,
        );
        // The cell is new, so the value is not set.
        let _ = playbook_cell.set(Arc::downgrade(&playbooks));

        let agents = if settings.agents.runtime.enabled_roles.is_empty() {
            None
        } else {
            let context = AgentContext {
                goal: settings.agents.goal.clone(),
                models: models.clone(),
                graph: stores.graph.clone(),
                incidents: shared_incidents,
                audit: audit_log.clone(),
                bus: bus.clone(),
            };
            let runtime = AgentRuntime::builder(context, action_dispatcher)
                .config(settings.agents.runtime.clone())
                .with_default_agents()
                .build()
                .map_err(|error| section_error("agents", error))?;
            Some(Arc::new(runtime))
        };

        let mut sources = SourceRegistry::from_configs(&settings.sources)
            .map_err(|error| section_error("sources", error))?;
        for source in plugins.sources.into_iter().chain(extra_sources) {
            sources
                .register(source)
                .map_err(|error| section_error("sources", error))?;
        }
        let checkpoints: Arc<dyn CheckpointStore> = match &settings.ingest.checkpoint_dir {
            Some(directory) => Arc::new(FileCheckpointStore::new(directory.clone())),
            None => Arc::new(MemoryCheckpointStore::new()),
        };

        let playbooks_enabled = settings.modules.contains(Module::Responder)
            && settings.response.playbooks != PlaybookMode::Off;
        let bridge = Arc::new(Bridge::new(
            bus.clone(),
            audit_log,
            incidents.clone(),
            agents.clone(),
            playbooks.clone(),
            playbooks_enabled,
            settings.agents.monitor_events,
            activity.clone(),
        ));

        Ok(Self {
            settings,
            activity,
            bus,
            graph: stores.graph,
            vectors: stores.vectors,
            incidents,
            approvals: stores.approvals,
            audit,
            models,
            has_model,
            policy,
            rbac,
            approval_service,
            action_registry,
            dispatcher,
            actions,
            playbooks,
            engine,
            agents,
            sources: Arc::new(sources),
            checkpoints,
            honeytokens,
            rotated_secrets,
            bridge,
            exclusive: tokio::sync::Mutex::new(()),
            service_runs: AtomicBool::new(false),
            start_recorded: AtomicBool::new(false),
            #[cfg(feature = "postgres")]
            postgres: stores.postgres,
        })
    }

    /// Opens the stores and the audit log that the configuration selects.
    async fn stores(settings: &Settings) -> Result<Stores> {
        #[cfg(feature = "postgres")]
        let postgres = match &settings.storage {
            StorageSettings::Memory => None,
            StorageSettings::Postgres(config) => {
                let store = aegis_storage::PgStore::connect(config)
                    .await
                    .map_err(|error| section_error("storage", error))?;
                store
                    .migrate()
                    .await
                    .map_err(|error| section_error("storage", error))?;
                Some(store)
            }
        };

        let file_audit = match &settings.audit {
            AuditSettings::File(config) => {
                if let Some(directory) = config.path.parent()
                    && !directory.as_os_str().is_empty()
                {
                    tokio::fs::create_dir_all(directory)
                        .await
                        .map_err(|error| {
                            Error::Config(format!(
                                "the section `audit` is not valid: cannot make the directory {}: \
                             {error}",
                                directory.display()
                            ))
                        })?;
                }
                let config = config.clone();
                let log = tokio::task::spawn_blocking(move || FileAuditLog::from_config(&config))
                    .await
                    .map_err(|error| Error::other("open the audit log", error))?
                    .map_err(|error| section_error("audit", error))?;
                let log: Arc<dyn AuditLog> = Arc::new(log);
                Some(log)
            }
            AuditSettings::Postgres => None,
        };

        #[cfg(feature = "postgres")]
        if let Some(store) = postgres {
            let audit: Arc<dyn AuditLog> = match file_audit {
                Some(log) => log,
                None => Arc::new(store.audit()),
            };
            return Ok(Stores {
                graph: Arc::new(store.graph()),
                vectors: Arc::new(store.vectors()),
                incidents: Arc::new(store.incidents()),
                approvals: Arc::new(store.approvals()),
                audit,
                postgres: Some(store),
            });
        }

        match (&settings.storage, file_audit) {
            (StorageSettings::Memory, Some(audit)) => Ok(Stores {
                graph: Arc::new(MemoryGraph::default()),
                vectors: Arc::new(MemoryVectors::default()),
                incidents: Arc::new(MemoryIncidents::default()),
                approvals: Arc::new(MemoryApprovals::default()),
                audit,
                #[cfg(feature = "postgres")]
                postgres: None,
            }),
            // The settings reject this combination. This arm keeps the build closed if a
            // later change lets it through.
            _ => Err(Error::Config(
                "the section `audit` is not valid: kind = \"postgres\" needs storage.kind = \
                 \"postgres\""
                    .to_owned(),
            )),
        }
    }

    #[cfg(feature = "plugins")]
    async fn plugins(settings: &Settings) -> Result<Plugins> {
        let Some(config) = &settings.plugins else {
            return Ok(Plugins::default());
        };
        let mut limits = aegis_plugin::HostLimits::default();
        if let Some(bytes) = config.limits.max_memory_bytes {
            limits.max_memory_bytes = bytes;
        }
        if let Some(seconds) = config.limits.call_timeout_seconds {
            limits.call_timeout = Duration::from_secs(seconds);
        }
        if let Some(calls) = config.limits.max_concurrent_calls {
            limits.max_concurrent_calls = calls;
        }
        if let Some(seconds) = config.limits.http_timeout_seconds {
            limits.http_timeout = Duration::from_secs(seconds);
        }
        if let Some(required) = config.limits.require_sha256 {
            limits.require_sha256 = required;
        }
        let host = aegis_plugin::PluginHost::new(limits)
            .map_err(|error| section_error("plugins", error))?;
        let loaded = host
            .load_dir(&config.dir)
            .await
            .map_err(|error| section_error("plugins", error))?;
        tracing::info!(
            sources = loaded.sources.len(),
            actions = loaded.actions.len(),
            "loaded the connector plugins"
        );
        Ok(Plugins {
            sources: loaded.sources,
            actions: loaded.actions,
        })
    }

    #[cfg(not(feature = "plugins"))]
    async fn plugins(_settings: &Settings) -> Result<Plugins> {
        // The settings reject a `[plugins]` section in a build without the feature.
        Ok(Plugins::default())
    }

    /// Makes the action registry. A connector that comes first has priority for an action
    /// type with no route.
    fn build_action_registry(
        settings: &Settings,
        extra: Vec<Arc<dyn ActionConnector>>,
        plugins: Vec<Arc<dyn ActionConnector>>,
        honeytokens: &Arc<HoneytokenRegistry>,
        rotated_secrets: &Arc<MemorySecretSink>,
    ) -> Result<ActionRegistry> {
        let response = &settings.response;
        let invalid = |error| section_error("response", error);
        let mut registry = ActionRegistry::new();
        for connector in extra {
            registry.register(connector).map_err(invalid)?;
        }
        if let Some(config) = &response.graph {
            let connector = GraphActionConnector::new(config.clone(), rotated_secrets.clone())
                .map_err(invalid)?;
            registry.register(Arc::new(connector)).map_err(invalid)?;
        }
        if let Some(config) = &response.webhook {
            let connector = WebhookConnector::new(config.clone()).map_err(invalid)?;
            registry.register(Arc::new(connector)).map_err(invalid)?;
        }
        for connector in plugins {
            registry.register(connector).map_err(invalid)?;
        }
        registry
            .register(Arc::new(HoneytokenConnector::new(
                HONEYTOKEN_CONNECTOR,
                honeytokens.clone(),
            )))
            .map_err(invalid)?;
        if response.dry_run && response.simulate_missing_connectors {
            registry
                .register(Arc::new(SimulationConnector))
                .map_err(invalid)?;
        }
        registry
            .apply_routes(response.routes.iter().cloned())
            .map_err(invalid)?;
        Ok(registry)
    }

    /// Returns the settings that the application was built from.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns the modules that the process runs.
    #[must_use]
    pub fn modules(&self) -> &ModuleSet {
        &self.settings.modules
    }

    /// Returns the message bus.
    #[must_use]
    pub fn bus(&self) -> Arc<dyn MessageBus> {
        self.bus.clone()
    }

    /// Returns the Defensive Graph.
    #[must_use]
    pub fn graph(&self) -> Arc<dyn DefensiveGraph> {
        self.graph.clone()
    }

    /// Returns the vector store.
    #[must_use]
    pub fn vectors(&self) -> Arc<dyn VectorStore> {
        self.vectors.clone()
    }

    /// Returns the incident store that all components share.
    #[must_use]
    pub fn incidents(&self) -> Arc<SharedIncidents> {
        self.incidents.clone()
    }

    /// Returns the audit log. Each record that it takes also goes to `aegis.audit`.
    #[must_use]
    pub fn audit(&self) -> Arc<PublishingAuditLog> {
        self.audit.clone()
    }

    /// Returns the approval queue. Use [`App::decide_approval`] to decide a request.
    #[must_use]
    pub fn approvals(&self) -> Arc<dyn ApprovalQueue> {
        self.approvals.clone()
    }

    /// Returns the model provider: the model router, or the offline provider.
    #[must_use]
    pub fn models(&self) -> Arc<dyn ModelProvider> {
        self.models.clone()
    }

    /// Returns `true` if the process has a model.
    #[must_use]
    pub fn has_model(&self) -> bool {
        self.has_model
    }

    /// Returns the policy engine.
    #[must_use]
    pub fn policy(&self) -> Arc<RegoPolicyEngine> {
        self.policy.clone()
    }

    /// Returns the role-based access control check.
    #[must_use]
    pub fn rbac(&self) -> Arc<Rbac> {
        self.rbac.clone()
    }

    /// Returns the approval service.
    #[must_use]
    pub fn approval_service(&self) -> Arc<ApprovalService> {
        self.approval_service.clone()
    }

    /// Returns the action dispatcher. Use it for `resume` and for the dry-run switch.
    #[must_use]
    pub fn dispatcher(&self) -> Arc<Dispatcher> {
        self.dispatcher.clone()
    }

    /// Returns the dispatcher with its journal. Send each new action request to this
    /// value, so that the journal has the request.
    #[must_use]
    pub fn actions(&self) -> Arc<ActionJournal> {
        self.actions.clone()
    }

    /// Returns the action registry.
    #[must_use]
    pub fn action_registry(&self) -> Arc<ActionRegistry> {
        self.action_registry.clone()
    }

    /// Returns the playbooks of the operator.
    #[must_use]
    pub fn playbooks(&self) -> Arc<Playbooks> {
        self.playbooks.clone()
    }

    /// Returns the detection engine.
    #[must_use]
    pub fn engine(&self) -> Arc<DetectionEngine> {
        self.engine.clone()
    }

    /// Returns the agent runtime. `None` means that the module set has no agent.
    #[must_use]
    pub fn agents(&self) -> Option<Arc<AgentRuntime>> {
        self.agents.clone()
    }

    /// Returns the source registry.
    #[must_use]
    pub fn sources(&self) -> Arc<SourceRegistry> {
        self.sources.clone()
    }

    /// Returns the honeytoken registry. The honeytoken connector and the honeytoken
    /// detector use this one registry.
    #[must_use]
    pub fn honeytokens(&self) -> Arc<HoneytokenRegistry> {
        self.honeytokens.clone()
    }

    /// Returns the receiver of the new secrets of credential rotations.
    ///
    /// The receiver keeps the secrets in memory. Move each secret to your vault before the
    /// process stops.
    #[must_use]
    pub fn rotated_secrets(&self) -> Arc<MemorySecretSink> {
        self.rotated_secrets.clone()
    }

    /// Returns the signal that changes at each change of the state of the application.
    #[must_use]
    pub fn activity(&self) -> Arc<Activity> {
        self.activity.clone()
    }

    /// Returns the counts of the work of the bridges.
    #[must_use]
    pub fn progress(&self) -> Progress {
        self.bridge.progress()
    }

    /// Waits until `condition` returns `true`, for `limit` at most.
    ///
    /// The function examines the condition after each change of the state of the
    /// application. It does not use a sleep.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the condition is not `true` at the end of `limit`.
    pub async fn wait_until<F, Fut>(&self, limit: Duration, condition: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        tokio::time::timeout(limit, self.activity.wait_until(condition))
            .await
            .map_err(|_| {
                Error::Timeout(format!(
                    "the application did not get to the expected state in {} seconds",
                    limit.as_secs()
                ))
            })
    }

    /// Closes the connections of the stores. Call this before the process stops.
    pub async fn close(&self) {
        #[cfg(feature = "postgres")]
        if let Some(store) = &self.postgres {
            store.close().await;
        }
    }

    /// Writes the audit record of the start, one time for each application.
    async fn record_start(&self) -> Result<()> {
        if self.start_recorded.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let pack = self.engine.pack();
        let policy = self.policy.version();
        let modules: Vec<&str> = self.settings.modules.iter().map(Module::name).collect();
        let entry = AuditEntry::new(
            AuditKind::ConfigChange,
            APP_ACTOR,
            format!(
                "AEGIS started with the rule pack {} {}, the policy {}, and {} playbooks.",
                pack.manifest().name,
                pack.manifest().version,
                policy.digest,
                self.playbooks.names().len()
            ),
        )
        .with_payload(json!({
            "modules": modules,
            "rule_pack": {
                "name": pack.manifest().name,
                "version": pack.manifest().version,
                "rules": pack.rules().len(),
                "indicators": pack.indicators().len(),
            },
            "policy": { "digest": policy.digest, "rule": policy.rule, "files": policy.policies },
            "playbooks": self.playbooks.names(),
            "playbook_mode": self.settings.response.playbooks,
            "dispatcher_dry_run": self.dispatcher.dry_run(),
            "agents_dry_run": self.settings.agents.runtime.dry_run,
            "storage": self.settings.storage.kind(),
            "model": self.has_model,
            "connectors": self.action_registry.names(),
            "sources": self.sources.names(),
        }));
        match self.audit.append(entry).await {
            Ok(_) => Ok(()),
            Err(error) => {
                self.start_recorded.store(false, Ordering::SeqCst);
                Err(error)
            }
        }
    }

    /// Runs the agent runtime until its queue is empty. Adds the counts to `total`.
    async fn drive_agents(&self, total: &mut RunReport) -> Result<()> {
        if let Some(runtime) = &self.agents
            && !runtime.is_idle()
        {
            let report = runtime.run_until_idle().await?;
            add_reports(total, &report);
        }
        Ok(())
    }

    /// Examines a list of events in the process and returns a report.
    ///
    /// The run is the same each time for the same events and the same configuration. For
    /// each event, the function does these steps in sequence:
    ///
    /// 1. The detection engine examines the event.
    /// 2. The bridge records each detection and writes each incident state to the store.
    /// 3. The agents work until their queue is empty.
    /// 4. The matching playbooks run, one time for each incident and playbook.
    ///
    /// The function does not start the source connectors and does not read events from
    /// the bus. It publishes the detections and the incidents on the bus.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] if [`App::run`] or a different replay is in
    /// progress. Returns the error of the audit log, the incident store, or the bus if one
    /// of them fails. The run then stops at that event.
    pub async fn replay<I>(&self, events: I) -> Result<ReplayReport>
    where
        I: IntoIterator<Item = Event>,
    {
        let _exclusive = self.exclusive.try_lock().map_err(|_| {
            Error::InvalidInput(
                "the application already runs: wait for the run or the replay to complete"
                    .to_owned(),
            )
        })?;
        self.record_start().await?;
        let journal_mark = self.actions.total();
        let mut count = 0_u64;
        let mut detections = Vec::new();
        let mut touched: Vec<IncidentId> = Vec::new();
        let mut playbook_runs = Vec::new();
        let mut agent_report = RunReport::default();

        for event in events {
            count += 1;
            self.bridge.observe_event(&event);
            let output = self.engine.process(&event).await?;
            let mut nudges = Vec::new();
            let mut for_playbooks = Vec::new();
            for detection in &output.detections {
                self.bridge.on_detection(detection).await?;
                self.bridge.publish_detection(detection).await?;
                detections.push(detection.clone());
            }
            for incident in &output.incidents {
                let update = self
                    .bridge
                    .on_engine_incident(incident, AgentFeed::Direct)
                    .await?;
                if update.merge.changed && !touched.contains(&incident.id) {
                    touched.push(incident.id);
                }
                if update.analyst_nudge {
                    nudges.push(update.merge.incident);
                }
                if update.playbooks {
                    for_playbooks.push(incident.id);
                }
            }
            // The Monitor writes the new data to the graph first. Then the Analyst gets an
            // incident that an agent moved past `open` before.
            self.drive_agents(&mut agent_report).await?;
            if !nudges.is_empty() {
                for incident in &nudges {
                    self.bridge.nudge_analyst(incident)?;
                }
                self.drive_agents(&mut agent_report).await?;
            }
            for incident_id in for_playbooks {
                playbook_runs.extend(self.bridge.run_playbooks(incident_id).await?);
            }
        }
        self.drive_agents(&mut agent_report).await?;

        let mut incidents = Vec::with_capacity(touched.len());
        for id in touched {
            if let Some(incident) = self.incidents.get(id).await? {
                incidents.push(incident);
            }
        }
        let verification = self.audit.verify().await?;
        Ok(ReplayReport {
            events: count,
            dry_run: self.dispatcher.dry_run(),
            model: self.has_model,
            detections,
            incidents,
            actions: self.actions.since(journal_mark),
            playbook_runs,
            agents: self.agents.as_ref().map(|_| agent_report),
            audit: AuditSummary {
                records: verification.checked,
                verification,
            },
        })
    }

    /// Runs the service until `shutdown` is triggered.
    ///
    /// Refer to [`App::run_with`].
    ///
    /// # Errors
    ///
    /// Returns the errors of [`App::run_with`].
    pub async fn run(&self, shutdown: Shutdown) -> Result<()> {
        self.run_with(shutdown, RunOptions::default())
            .await
            .map(|_| ())
    }

    /// Runs the service until `shutdown` is triggered, with options.
    ///
    /// The function starts these components for the modules in the module set:
    ///
    /// | Module | Component |
    /// | --- | --- |
    /// | `ingest` | One ingestion runner for each source. |
    /// | `detection` | The bus runner of the detection engine, with the bridges. |
    /// | An agent module | The agent runtime. It reads incidents and tasks from the bus. |
    /// | `responder` | The playbook worker, if `response.playbooks` is not `off`. |
    /// | `api` | The service of `options` for the module `api`: the operator API. |
    ///
    /// It also starts the other services of `options`. After the shutdown signal, each
    /// component completes the work that is in progress, and the function returns.
    ///
    /// # Errors
    ///
    /// If one component fails, the function stops all components and returns the error of
    /// the component that failed first. Returns [`Error::InvalidInput`] if a run or a
    /// replay is in progress. Returns [`Error::Config`] if the module set has `api` and
    /// `options` has no service for that module.
    pub async fn run_with(&self, shutdown: Shutdown, options: RunOptions) -> Result<RunSummary> {
        let _exclusive = self.exclusive.try_lock().map_err(|_| {
            Error::InvalidInput(
                "the application already runs: wait for the run or the replay to complete"
                    .to_owned(),
            )
        })?;
        let modules = &self.settings.modules;
        if modules.contains(Module::Api)
            && !options
                .services
                .iter()
                .any(|service| service.module == Some(Module::Api))
        {
            return Err(Error::Config(
                "the section `modules` is not valid: the module `api` is enabled, but this \
                 program has no operator API"
                    .to_owned(),
            ));
        }
        self.record_start().await?;
        self.service_runs.store(true, Ordering::SeqCst);
        let _flag = ServiceFlag(&self.service_runs);

        // `stop` follows the signal of the caller. A failure of one component triggers
        // only `stop`, so the signal of the caller stays as it is.
        let stop = shutdown.child();
        let cancel = CancellationToken::new();
        let mut tasks: JoinSet<TaskEnd> = JoinSet::new();
        tasks.spawn({
            let (stop, cancel) = (stop.clone(), cancel.clone());
            async move {
                stop.wait().await;
                cancel.cancel();
                TaskEnd::Helper
            }
        });

        let detection_runs = modules.contains(Module::Detection);
        if detection_runs {
            let (jobs, mut job_queue) = mpsc::unbounded_channel::<IncidentId>();
            let bus = DetectionBus::new(self.bus.clone(), self.bridge.clone(), jobs);
            let engine = self.engine.clone();
            let config = self.settings.detection.runner.clone();
            let token = cancel.clone();
            tasks.spawn(async move { TaskEnd::Detection(engine.run(&bus, &config, token).await) });

            let bridge = self.bridge.clone();
            let token = cancel.clone();
            tasks.spawn(async move {
                loop {
                    let job = tokio::select! {
                        biased;
                        () = token.cancelled() => break,
                        job = job_queue.recv() => job,
                    };
                    let Some(incident_id) = job else {
                        break;
                    };
                    // One playbook run that fails must not stop the detection. The error
                    // goes to the log, and the audit log has each request that ran.
                    if let Err(error) = bridge.run_playbooks(incident_id).await {
                        tracing::error!(
                            incident = %incident_id,
                            %error,
                            "the playbooks did not run for an incident"
                        );
                    }
                }
                TaskEnd::Helper
            });
        }

        let mut agents_before = None;
        if let Some(runtime) = &self.agents {
            agents_before = Some(runtime.stats());
            if runtime.roster().has(&AgentRole::Supervisor) {
                runtime.submit_goal(self.settings.agents.goal.clone())?;
            }
            let runtime = runtime.clone();
            let token = cancel.clone();
            tasks.spawn(async move { TaskEnd::Agents(runtime.run(token).await) });
        }

        let mut ingest_remaining = 0_usize;
        if modules.contains(Module::Ingest) {
            let tap: Arc<dyn MessageBus> =
                Arc::new(IngestTap::new(self.bus.clone(), self.bridge.clone()));
            let runners =
                self.sources
                    .runners(&tap, &self.checkpoints, &cancel, self.settings.ingest.retry);
            let runners = match runners {
                Ok(runners) => runners,
                Err(error) => {
                    stop.trigger();
                    while tasks.join_next().await.is_some() {}
                    return Err(section_error("sources", error));
                }
            };
            ingest_remaining = runners.len();
            for runner in runners {
                tasks.spawn(async move {
                    let result = runner.run().await;
                    TaskEnd::Ingest {
                        name: runner.name().to_owned(),
                        result,
                        stats: runner.stats(),
                    }
                });
            }
        }

        for service in options.services {
            if service
                .module
                .is_some_and(|module| !modules.contains(module))
            {
                continue;
            }
            let Service { name, start, .. } = service;
            let work = start(stop.clone());
            tasks.spawn(async move {
                TaskEnd::Service {
                    name,
                    result: work.await,
                }
            });
        }
        tracing::info!(
            sources = ingest_remaining,
            detection = detection_runs,
            agents = self.agents.is_some(),
            "the service started"
        );

        let mut summary = RunSummary::default();
        let mut first_error: Option<Error> = None;
        let mut fail = |error: Error, component: &str, stop: &Shutdown| {
            tracing::error!(component, %error, "a component failed; the service stops");
            if first_error.is_none() {
                first_error = Some(error);
            }
            stop.trigger();
        };
        let mut drain_started = false;
        if options.stop_when_sources_end && ingest_remaining == 0 {
            stop.trigger();
        }
        while let Some(joined) = tasks.join_next().await {
            let end = match joined {
                Ok(end) => end,
                Err(error) => {
                    fail(Error::other("a service component", error), "task", &stop);
                    continue;
                }
            };
            match end {
                TaskEnd::Ingest {
                    name,
                    result,
                    stats,
                } => {
                    ingest_remaining = ingest_remaining.saturating_sub(1);
                    match result {
                        Ok(outcome) => summary.sources.push(SourceSummary {
                            name,
                            outcome,
                            stats,
                        }),
                        Err(error) => fail(error, "ingest", &stop),
                    }
                    if options.stop_when_sources_end && ingest_remaining == 0 && !drain_started {
                        drain_started = true;
                        if detection_runs {
                            let (bridge, activity, stop) =
                                (self.bridge.clone(), self.activity.clone(), stop.clone());
                            tasks.spawn(async move {
                                let caught_up = activity.wait_until(|| {
                                    let bridge = bridge.clone();
                                    async move { bridge.caught_up() }
                                });
                                tokio::select! {
                                    () = caught_up => stop.trigger(),
                                    () = stop.wait() => {}
                                }
                                TaskEnd::Helper
                            });
                        } else {
                            stop.trigger();
                        }
                    }
                }
                TaskEnd::Detection(Ok(_)) | TaskEnd::Helper => {}
                TaskEnd::Detection(Err(error)) => fail(error, "detection", &stop),
                TaskEnd::Agents(Ok(_)) => {}
                TaskEnd::Agents(Err(error)) => fail(error, "agents", &stop),
                TaskEnd::Service { result: Ok(()), .. } => {}
                TaskEnd::Service {
                    name,
                    result: Err(error),
                } => fail(error, &name, &stop),
            }
        }
        summary.progress = self.bridge.progress();
        summary.agents = match (&self.agents, agents_before) {
            (Some(runtime), Some(before)) => Some(runtime.stats().since(&before)),
            _ => None,
        };
        tracing::info!("the service stopped");
        match first_error {
            Some(error) => Err(error),
            None => Ok(summary),
        }
    }

    /// Records the decision of a person on an approval request, and runs the action if
    /// the person approved it.
    ///
    /// The steps are:
    ///
    /// 1. The approval service checks the permission and the approval rules, writes the
    ///    audit record, and records the decision.
    /// 2. For an approval, the dispatcher evaluates the policy again and runs the action
    ///    one time.
    /// 3. The agent that proposed the action gets the result. For a rejection, the agent
    ///    gets a denial with the policy name [`APPROVAL_REJECTED_POLICY`].
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`] if `principal` has no permission to approve, or an
    ///   approval rule does not permit the decision. The request stays pending.
    /// - [`Error::NotFound`] if the request does not exist.
    /// - [`Error::InvalidInput`] if the request already has a decision.
    /// - The error of the connector, if the approved action fails. The decision stays
    ///   recorded, and one approval permits one attempt.
    pub async fn decide_approval(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalOutcome> {
        let decided = self.record_decision(id, approve, principal, note).await?;
        match decided.failure {
            Some(error) => Err(error),
            None => Ok(ApprovalOutcome {
                approval: decided.approval,
                disposition: decided.disposition,
            }),
        }
    }

    /// Does the steps of [`App::decide_approval`], and keeps the decided request when a
    /// step after the record of the decision fails.
    ///
    /// # Errors
    ///
    /// Returns the error of the approval service. The request then has no new decision.
    /// A failure after the record of the decision is in [`Decided::failure`].
    pub(crate) async fn record_decision(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> Result<Decided> {
        let approval = self
            .approval_service
            .decide(id, approve, principal, note)
            .await?;
        if let Err(error) = publish_json(self.bus.as_ref(), subject::APPROVALS, &approval).await {
            tracing::warn!(approval = %id, %error, "the bus did not take the decided approval");
        }
        let action_id = approval.action.id;

        if !approve {
            let mut reason = format!("{} rejected the approval request {id}.", principal.id);
            if let Some(note) = approval
                .note
                .as_deref()
                .filter(|note| !note.trim().is_empty())
            {
                reason.push_str(" Note: ");
                reason.push_str(&note.split_whitespace().collect::<Vec<_>>().join(" "));
            }
            let denial = ActionDisposition::Denied(PolicyDecision {
                effect: PolicyEffect::Deny,
                tier: approval.decision.tier,
                reasons: vec![reason],
                policy: Some(APPROVAL_REJECTED_POLICY.to_owned()),
                evaluated_at: Utc::now(),
            });
            self.actions
                .set_result(action_id, DispatchResult::Disposition(denial.clone()));
            let failure = self.give_result_to_agent(&approval, denial).await.err();
            return Ok(Decided {
                approval,
                disposition: None,
                failure,
            });
        }

        match self.dispatcher.resume(id).await {
            Ok(disposition) => {
                self.actions
                    .set_result(action_id, DispatchResult::Disposition(disposition.clone()));
                let failure = self
                    .give_result_to_agent(&approval, disposition.clone())
                    .await
                    .err();
                Ok(Decided {
                    approval,
                    disposition: Some(disposition),
                    failure,
                })
            }
            Err(error) => {
                self.actions
                    .set_result(action_id, DispatchResult::from_error(&error));
                let failed = ActionDisposition::Executed(ActionOutcome {
                    action_id,
                    status: ActionStatus::Failed,
                    connector: String::new(),
                    message: error.to_string(),
                    details: serde_json::Value::Null,
                    reversible: false,
                    completed_at: Utc::now(),
                });
                if let Err(agent_error) = self.give_result_to_agent(&approval, failed.clone()).await
                {
                    tracing::error!(
                        approval = %id,
                        error = %agent_error,
                        "the agent did not get the failure of an approved action"
                    );
                }
                Ok(Decided {
                    approval,
                    disposition: Some(failed),
                    failure: Some(error),
                })
            }
        }
    }

    /// Gives the result of a decided approval to the agent that proposed the action.
    async fn give_result_to_agent(
        &self,
        approval: &ApprovalRequest,
        disposition: ActionDisposition,
    ) -> Result<()> {
        let Some(runtime) = &self.agents else {
            return Ok(());
        };
        let Some(role) = agent_role(&approval.requested_by) else {
            return Ok(());
        };
        if !runtime.roster().has(&role) {
            return Ok(());
        }
        // The task has the identifier of the action, as the agent runtime makes it.
        let task = AgentTask {
            id: TaskId(approval.action.id.0),
            to: role,
            from: None,
            incident_id: approval.action.incident_id,
            input: AgentInput::ActionResult(Box::new(disposition)),
            created_at: Utc::now(),
        };
        runtime.submit(task)?;
        if self.service_runs.load(Ordering::SeqCst) {
            // The service drives the queue of the agents.
            return Ok(());
        }
        let _exclusive = self.exclusive.lock().await;
        if !self.service_runs.load(Ordering::SeqCst) && !runtime.is_idle() {
            runtime.run_until_idle().await?;
        }
        Ok(())
    }

    /// Loads the rule pack, the policy, and the playbooks again from their files.
    ///
    /// The function reads and checks all three first. If one of them is not valid, the
    /// function returns the error, and all three stay as they were. After a successful
    /// reload, the function writes an [`AuditKind::ConfigChange`] record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] with the name of the section if a file is not valid.
    /// Returns the error of the audit log if the record cannot be written. The new state
    /// is then active.
    pub async fn reload(&self) -> Result<ReloadReport> {
        self.reload_as(APP_ACTOR).await
    }

    /// Does [`App::reload`] for `principal`, which must have the permission
    /// `manage_policy`. The audit record names the principal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if `principal` does not have the permission.
    /// Returns the errors of [`App::reload`].
    pub async fn reload_by(&self, principal: &Principal) -> Result<ReloadReport> {
        self.rbac.check(principal, Permission::ManagePolicy)?;
        self.reload_as(&principal.id).await
    }

    async fn reload_as(&self, actor: &str) -> Result<ReloadReport> {
        let pack_dir = self.settings.detection.pack.clone();
        let pack = tokio::task::spawn_blocking(move || RulePack::load(pack_dir))
            .await
            .map_err(|error| Error::other("load the rule pack", error))?
            .map_err(|error| section_error("detection", error.into()))?;
        let playbooks = self
            .playbooks
            .prepare()
            .await
            .map_err(|error| section_error("response", error))?;
        // The policy engine checks the new policy and then makes it active in one step.
        // It is the last check, so a failure here leaves all three as they were.
        let policy = self
            .policy
            .reload()
            .map_err(|error| section_error("policy", error))?;
        let report = ReloadReport {
            pack: pack.manifest().name.clone(),
            pack_version: pack.manifest().version.clone(),
            rules: pack.rules().len(),
            indicators: pack.indicators().len(),
            policy_digest: policy.digest.clone(),
            playbooks: Vec::new(),
        };
        self.engine.reload(pack);
        let report = ReloadReport {
            playbooks: self.playbooks.activate(playbooks),
            ..report
        };

        let entry = AuditEntry::new(
            AuditKind::ConfigChange,
            actor,
            format!(
                "{actor} loaded the rule pack {} {}, the policy {}, and {} playbooks again.",
                report.pack,
                report.pack_version,
                report.policy_digest,
                report.playbooks.len()
            ),
        )
        .with_payload(json!({
            "rule_pack": {
                "name": report.pack,
                "version": report.pack_version,
                "rules": report.rules,
                "indicators": report.indicators,
            },
            "policy": { "digest": policy.digest, "rule": policy.rule, "files": policy.policies },
            "playbooks": report.playbooks,
        }));
        self.audit.append(entry).await?;
        Ok(report)
    }

    /// Returns the path of the audit log file, if the audit log is a file.
    #[must_use]
    pub fn audit_path(&self) -> Option<&Path> {
        match &self.settings.audit {
            AuditSettings::File(config) => Some(&config.path),
            AuditSettings::Postgres => None,
        }
    }
}
