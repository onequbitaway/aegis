//! The application: all subsystems of one AEGIS process, built from one configuration.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use aegis_agents::{AgentRuntime, BUILT_IN_ROLES, RunReport};
use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionOutcome, ActionStatus,
};
use aegis_contracts::audit::{AuditEntry, AuditKind, AuditLog};
use aegis_contracts::bus::{MessageBus, publish_json, subject};
use aegis_contracts::common::{ActionId, ApprovalId, IncidentId, TaskId};
use aegis_contracts::event::Event;
use aegis_contracts::graph::{DefensiveGraph, VectorStore};
use aegis_contracts::incident::{Incident, IncidentStore};
use aegis_contracts::model::ModelProvider;
use aegis_contracts::policy::{
    ApprovalQueue, ApprovalRequest, PolicyDecision, PolicyEffect, Principal, PrincipalKind,
};
use aegis_contracts::source::SourceConnector;
use aegis_contracts::{AgentContext, AgentInput, AgentRole, AgentTask, Error, Result};
use aegis_core::{Config, Module, ModuleSet, Shutdown};
use aegis_detect::{DetectionEngine, FloodCounters, IncidentCoalescer, RulePack};
use aegis_ingest::{
    CheckpointStore, FileCheckpointStore, IngestStats, MemoryCheckpointStore, RunOutcome,
    SourceRegistry,
};
use aegis_memory::{MemoryApprovals, MemoryGraph, MemoryIncidents, MemoryVectors};
use aegis_policy::{ApprovalService, FileAuditLog, Permission, Rbac, RegoPolicyEngine};
use aegis_respond::{
    ActionRegistry, Dispatcher, FileRevertStore, GraphActionConnector, HoneytokenConnector,
    HoneytokenRegistry, HoneytokenTripDetector, MemoryHoneytokenStore, MemorySecretSink,
    PendingRevert, PlaybookRun, RevertScheduler, RevertSchedulerConfig, RevertStore,
    WebhookConnector,
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
use crate::evidence::EvidenceArchive;
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
    #[cfg(feature = "decoy")]
    decoy_env: crate::decoy::EnvLookup,
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

    /// Sets the function that returns the value of an environment variable for the decoy
    /// service: the seed and the decoy keys. The default reads the environment of the
    /// process. Use this function in a test.
    #[cfg(feature = "decoy")]
    #[must_use]
    pub fn decoy_env(
        mut self,
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.decoy_env = Arc::new(env);
        self
    }

    /// Ignores the `[[sources]]` of the configuration. Only the sources of
    /// [`AppBuilder::source`] and of the plugins remain. The decoy service of the
    /// `[decoy]` section is also a configured source, so it does not start.
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
            #[cfg(feature = "decoy")]
            {
                settings.decoy = None;
            }
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
            // A local session opens no listener of the configuration.
            #[cfg(feature = "decoy")]
            {
                settings.decoy = None;
            }
        }
        if let Some(audit_file) = self.audit_file {
            // A second application on a host must not share the files of the service. One
            // scheduler uses one revert store, so this application has no revert store:
            // it refuses an action with a revert time that is not a dry run. The evidence
            // archive also has one writer, so this application has no archive.
            settings.response.revert = None;
            settings.evidence = None;
            settings.audit = AuditSettings::File(aegis_policy::FileAuditLogConfig {
                path: if audit_file.is_absolute() {
                    audit_file
                } else {
                    base_dir.join(audit_file)
                },
            });
        }
        let app = App::assemble(settings, self.model, self.action_connectors, self.sources).await?;
        #[cfg(feature = "decoy")]
        let app = App {
            decoy: crate::decoy::DecoyRuntime::new(self.decoy_env),
            ..app
        };
        Ok(app)
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
    /// The scheduler of the timed reverts. `None` if the timed revert is off.
    reverts: Option<RevertScheduler>,
    /// The evidence archive. `None` if the archive is off.
    evidence: Option<Arc<EvidenceArchive>>,
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
    /// The incident states that [`App::replay`] did not use, because a newer state of the
    /// same incident replaced them.
    replay_coalesced: AtomicU64,
    /// The decoy service: its secrets, and its handle while the service runs.
    #[cfg(feature = "decoy")]
    decoy: crate::decoy::DecoyRuntime,
    #[cfg(feature = "postgres")]
    postgres: Option<aegis_storage::PgStore>,
}

/// The work of one replay on its incidents.
#[derive(Default)]
struct ReplayWork {
    /// The incidents that changed, in the order of their first change.
    touched: Vec<IncidentId>,
    playbook_runs: Vec<PlaybookRun>,
    agents: RunReport,
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
    /// The ingestion runner of the decoy service. The decoy is a live source that has no
    /// end, so it is not one of the sources that a session on recorded events waits for.
    #[cfg(feature = "decoy")]
    Decoy {
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
            #[cfg(feature = "decoy")]
            decoy_env: crate::decoy::process_env(),
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
        // Each decoy key of the decoy service is a honeytoken with the identifier of the
        // key. Thus the honeytoken detector and the decoy agree on each key.
        #[cfg(feature = "decoy")]
        if let Some(decoy) = &settings.decoy {
            crate::decoy::register_keys(&honeytokens, decoy)
                .await
                .map_err(|error| section_error(crate::settings::DECOY_SECTION, error))?;
        }

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
        // The evidence archive: each detection with its events, and each state of an
        // incident. The sharing commands read it.
        let evidence = match &settings.evidence {
            Some(evidence) => {
                let (path, max_bytes) = (evidence.path.clone(), evidence.max_bytes);
                let archive =
                    tokio::task::spawn_blocking(move || EvidenceArchive::open(path, max_bytes))
                        .await
                        .map_err(|error| Error::other("open the evidence archive", error))?
                        .map_err(|error| section_error(crate::settings::EVIDENCE_SECTION, error))?;
                Some(Arc::new(archive))
            }
            None => None,
        };
        let incidents = Arc::new(
            SharedIncidents::new(stores.incidents.clone(), activity.clone())
                .on_written({
                    let evidence = evidence.clone();
                    move |incident| {
                        if let Some(archive) = &evidence {
                            archive.record_incident(incident);
                        }
                    }
                })
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
        let mut dispatcher = Dispatcher::builder(
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
        ));
        // The timed revert: the dispatcher keeps each pending revert in a file, so that a
        // restart does not lose it. A file that is not readable stops the build.
        if let Some(revert) = &settings.response.revert {
            let store: Arc<dyn RevertStore> = Arc::new(
                FileRevertStore::open(revert.store.clone())
                    .await
                    .map_err(|error| section_error("response", error))?,
            );
            dispatcher = dispatcher.revert_store(store);
        }
        let dispatcher = Arc::new(dispatcher.build());
        let reverts = match &settings.response.revert {
            Some(revert) => Some(
                RevertScheduler::with_config(
                    dispatcher.clone(),
                    RevertSchedulerConfig {
                        retry_base: Duration::from_secs(revert.retry_base_seconds),
                        retry_max: Duration::from_secs(revert.retry_max_seconds),
                        approval_poll: Duration::from_secs(revert.approval_poll_seconds),
                    },
                )
                .map_err(|error| section_error("response", error))?,
            ),
            None => None,
        };
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
        let bridge = Arc::new(
            Bridge::new(
                bus.clone(),
                audit_log,
                incidents.clone(),
                agents.clone(),
                playbooks.clone(),
                playbooks_enabled,
                settings.agents.monitor_events,
                activity.clone(),
            )
            .with_evidence(evidence.clone()),
        );

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
            reverts,
            evidence,
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
            replay_coalesced: AtomicU64::new(0),
            #[cfg(feature = "decoy")]
            decoy: crate::decoy::DecoyRuntime::new(crate::decoy::process_env()),
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

    /// Returns the scheduler of the timed reverts. `None` means that the timed revert is
    /// off: the configuration has no `[response.revert]` table.
    ///
    /// [`App::run_with`] runs the scheduler. Use [`App::confirm_revert`],
    /// [`App::extend_revert`], and [`App::cancel_revert`] for the decisions of a person:
    /// they check the permission of the principal.
    #[must_use]
    pub fn revert_scheduler(&self) -> Option<RevertScheduler> {
        self.reverts.clone()
    }

    /// Returns the evidence archive. `None` means that the archive is off: the
    /// configuration has no `[evidence]` section.
    #[must_use]
    pub fn evidence(&self) -> Option<Arc<EvidenceArchive>> {
        self.evidence.clone()
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

    /// Returns the counts of the flood protection of the detection engine, from the start
    /// of the process.
    ///
    /// `coalesced_incident_updates` also counts the incident states that [`App::replay`]
    /// did not use.
    #[must_use]
    pub fn flood_counters(&self) -> FloodCounters {
        let mut counters = self.engine.flood_counters();
        counters.coalesced_incident_updates = counters
            .coalesced_incident_updates
            .saturating_add(self.replay_coalesced.load(Ordering::Relaxed));
        counters
    }

    /// Returns the fields that the status route of the operator API adds to its
    /// document: the timed reverts, the evidence archive, and the decoy service.
    pub async fn status_sections(&self) -> BTreeMap<String, serde_json::Value> {
        let mut sections = BTreeMap::new();
        let reverts = match &self.reverts {
            Some(scheduler) => {
                let stats = scheduler.stats();
                // A store that does not answer gives no count. The status route still
                // answers.
                let pending = scheduler.pending().await.ok().map(|pending| pending.len());
                json!({
                    "enabled": true,
                    "pending": pending,
                    "reverted": stats.reverted,
                    "failed_attempts": stats.failed_attempts,
                    "confirmed": stats.confirmed,
                    "extended": stats.extended,
                    "cancelled": stats.cancelled,
                    "closed": stats.closed,
                })
            }
            None => json!({ "enabled": false }),
        };
        sections.insert("reverts".to_owned(), reverts);
        let evidence = match &self.evidence {
            Some(archive) => {
                let stats = archive.stats();
                json!({
                    "enabled": true,
                    "records_written": stats.records_written,
                    "bytes_written": stats.bytes_written,
                    "records_dropped": stats.records_dropped,
                    "rotations": stats.rotations,
                })
            }
            None => json!({ "enabled": false }),
        };
        sections.insert("evidence".to_owned(), evidence);
        #[cfg(feature = "decoy")]
        if let Some(config) = &self.settings.decoy {
            sections.insert("decoy".to_owned(), self.decoy.status(config));
        }
        sections
    }

    /// Returns the address on which the decoy service listens. `None` means that the
    /// decoy does not run: the configuration has no `[decoy]` section, the module `ingest`
    /// is not in the module set, or the service does not run.
    #[cfg(feature = "decoy")]
    #[must_use]
    pub fn decoy_address(&self) -> Option<std::net::SocketAddr> {
        self.decoy.address()
    }

    /// Checks the `[decoy]` section with its secrets: the seed and the decoy keys. Opens
    /// no socket. The function does nothing if the configuration has no decoy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if an environment variable that the section names is not
    /// set, or if its value is not usable. The message names the section and the
    /// variable. It never shows a secret.
    #[cfg(feature = "decoy")]
    pub fn check_decoy(&self) -> Result<()> {
        match &self.settings.decoy {
            Some(config) => self
                .decoy
                .check(config)
                .map_err(|error| section_error(crate::settings::DECOY_SECTION, error)),
            None => Ok(()),
        }
    }

    /// Returns `true` if [`App::run_with`] starts the decoy service: the configuration has
    /// the `[decoy]` section, and the module `ingest` is in the module set.
    #[cfg(feature = "decoy")]
    #[must_use]
    pub fn runs_decoy(&self) -> bool {
        self.settings.decoy.is_some() && self.settings.modules.contains(Module::Ingest)
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
            "timed_revert": self.reverts.is_some(),
            "evidence_archive": self.evidence.is_some(),
            "decoy": self.decoy_name(),
        }));
        match self.audit.append(entry).await {
            Ok(_) => Ok(()),
            Err(error) => {
                self.start_recorded.store(false, Ordering::SeqCst);
                Err(error)
            }
        }
    }

    /// Returns the name of the decoy service that a service run starts.
    fn decoy_name(&self) -> Option<&str> {
        #[cfg(feature = "decoy")]
        if self.runs_decoy() {
            return self.settings.decoy.as_ref().map(|decoy| decoy.id.as_str());
        }
        None
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
        let mut work = ReplayWork::default();
        // The limit on the states of one incident that the service has. Refer to
        // `detection.runner.max_incident_updates`. A flood of detections for one incident
        // thus gives a limited number of agent tasks and audit records.
        let runner = &self.settings.detection.runner;
        let mut coalescer = IncidentCoalescer::new(
            runner.max_incident_updates,
            runner.incident_update_window_seconds,
        )
        .map_err(|error| section_error("detection", error.into()))?;

        for event in events {
            count += 1;
            self.bridge.observe_event(&event);
            let output = self.engine.process(&event).await?;
            for detection in &output.detections {
                self.bridge.on_detection(detection).await?;
                self.bridge.publish_detection(detection).await?;
            }
            detections.extend(output.detections);
            // The new states go first. A new state replaces a held state of its incident.
            let mut states = Vec::with_capacity(output.incidents.len());
            for incident in output.incidents {
                states.extend(coalescer.offer(incident, event.time));
            }
            states.extend(coalescer.release_due(event.time));
            self.replay_states(&states, &mut work).await?;
        }
        // The stream of events stopped. A held state is the newest state of its incident.
        let held = coalescer.flush();
        self.replay_coalesced
            .fetch_add(coalescer.coalesced(), Ordering::Relaxed);
        if !held.is_empty() {
            self.replay_states(&held, &mut work).await?;
        }
        self.drive_agents(&mut work.agents).await?;

        let mut incidents = Vec::with_capacity(work.touched.len());
        for id in work.touched {
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
            playbook_runs: work.playbook_runs,
            agents: self.agents.as_ref().map(|_| work.agents),
            audit: AuditSummary {
                records: verification.checked,
                verification,
            },
        })
    }

    /// Takes the incident states of one step of a replay: the store, the agents, and the
    /// playbooks.
    async fn replay_states(&self, states: &[Incident], work: &mut ReplayWork) -> Result<()> {
        let mut nudges = Vec::new();
        let mut for_playbooks = Vec::new();
        for incident in states {
            let update = self
                .bridge
                .on_engine_incident(incident, AgentFeed::Direct)
                .await?;
            if update.merge.changed && !work.touched.contains(&incident.id) {
                work.touched.push(incident.id);
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
        self.drive_agents(&mut work.agents).await?;
        if !nudges.is_empty() {
            for incident in &nudges {
                self.bridge.nudge_analyst(incident)?;
            }
            self.drive_agents(&mut work.agents).await?;
        }
        for incident_id in for_playbooks {
            work.playbook_runs
                .extend(self.bridge.run_playbooks(incident_id).await?);
        }
        Ok(())
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
    /// | `ingest` | One ingestion runner for each source. The decoy service, if the configuration has the `[decoy]` section. |
    /// | `detection` | The bus runner of the detection engine, with the bridges. |
    /// | An agent module | The agent runtime. It reads incidents and tasks from the bus. |
    /// | `responder` | The playbook worker, if `response.playbooks` is not `off`. |
    /// | `api` | The service of `options` for the module `api`: the operator API. |
    ///
    /// It also starts the revert scheduler, if the configuration has the
    /// `[response.revert]` table, and the other services of `options`. After the shutdown
    /// signal, each component completes the work that is in progress, and the function
    /// returns.
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

        // The revert scheduler reads the pending reverts of the store when it starts.
        // Thus it continues the timed reverts from before a restart.
        if let Some(scheduler) = &self.reverts {
            let (scheduler, stop) = (scheduler.clone(), stop.clone());
            tasks.spawn(async move {
                scheduler.run(async move { stop.wait().await }).await;
                TaskEnd::Helper
            });
        }

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
            // The decoy service: a listener for clients that have no permission, and one
            // ingestion runner for its events.
            #[cfg(feature = "decoy")]
            if let Some(config) = &self.settings.decoy {
                let started = match self.decoy.bind(config).await {
                    Ok(bound) => aegis_ingest::IngestRunner::new(
                        Arc::new(bound.service()),
                        tap.clone(),
                        self.checkpoints.clone(),
                        // The runner has a signal of its own. Thus it publishes the last
                        // events of the decoy, and it completes when the stream ends.
                        CancellationToken::new(),
                    )
                    .map(|runner| (bound, runner.with_retry(self.settings.ingest.retry))),
                    Err(error) => Err(error),
                };
                let (bound, runner) = match started {
                    Ok(started) => started,
                    Err(error) => {
                        self.decoy.stopped();
                        stop.trigger();
                        while tasks.join_next().await.is_some() {}
                        return Err(section_error(crate::settings::DECOY_SECTION, error));
                    }
                };
                self.activity.bump();
                let token = cancel.clone();
                tasks.spawn(async move {
                    bound.serve(token).await;
                    TaskEnd::Helper
                });
                tasks.spawn(async move {
                    let result = runner.run().await;
                    TaskEnd::Decoy {
                        name: runner.name().to_owned(),
                        result,
                        stats: runner.stats(),
                    }
                });
            }
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
                #[cfg(feature = "decoy")]
                TaskEnd::Decoy {
                    name,
                    result,
                    stats,
                } => {
                    self.decoy.stopped();
                    match result {
                        Ok(outcome) => summary.sources.push(SourceSummary {
                            name,
                            outcome,
                            stats,
                        }),
                        Err(error) => fail(error, "decoy", &stop),
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

    /// Returns the scheduler of the timed reverts, or the error for a process in which
    /// the timed revert is off.
    fn timed_reverts(&self) -> Result<&RevertScheduler> {
        self.reverts.as_ref().ok_or_else(|| {
            Error::Unsupported(
                "the timed revert is off: the configuration has no `[response.revert]` table"
                    .to_owned(),
            )
        })
    }

    /// Lists the timed reverts that wait for their time or for a person. The revert with
    /// the earliest time is first.
    ///
    /// The list is empty if the timed revert is off.
    ///
    /// # Errors
    ///
    /// Returns the error of the revert store.
    pub async fn pending_reverts(&self) -> Result<Vec<PendingRevert>> {
        match &self.reverts {
            Some(scheduler) => scheduler.pending().await,
            None => Ok(Vec::new()),
        }
    }

    /// Confirms an action that has a timed revert. The containment stays.
    ///
    /// The scheduler writes an audit record with the principal before it removes the
    /// pending revert.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`] if `principal` does not have the permission
    ///   `approve_actions`, or is not a person.
    /// - [`Error::NotFound`] if the action has no pending revert.
    /// - [`Error::Unsupported`] if the timed revert is off.
    pub async fn confirm_revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> Result<PendingRevert> {
        self.rbac.check(principal, Permission::ApproveActions)?;
        self.timed_reverts()?.confirm(action_id, principal).await
    }

    /// Moves the revert time of an action by `extension`.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`] if `principal` does not have the permission
    ///   `approve_actions`, or is not a person.
    /// - [`Error::InvalidInput`] if `extension` is less than one second, or the new time
    ///   is more than 30 days from the present time.
    /// - [`Error::NotFound`] if the action has no pending revert.
    /// - [`Error::Unsupported`] if the timed revert is off.
    pub async fn extend_revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
        extension: Duration,
    ) -> Result<PendingRevert> {
        self.rbac.check(principal, Permission::ApproveActions)?;
        self.timed_reverts()?
            .extend(action_id, principal, extension)
            .await
    }

    /// Reverts an action with a timed revert immediately, before its revert time.
    ///
    /// The revert is a request of its own. It goes through the policy, the approval
    /// queue, and the audit log, with `principal`. If the result is not a completed
    /// revert, the pending revert stays.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`] if `principal` does not have the permission
    ///   `approve_actions`.
    /// - [`Error::NotFound`] if the action has no pending revert.
    /// - [`Error::Unsupported`] if the timed revert is off.
    /// - The errors of [`Dispatcher::revert`].
    pub async fn cancel_revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        self.rbac.check(principal, Permission::ApproveActions)?;
        let disposition = self.timed_reverts()?.cancel(action_id, principal).await?;
        self.activity.bump();
        Ok(disposition)
    }

    /// Reverts one action that a connector did before, with or without a timed revert.
    ///
    /// The revert is a request of its own. It goes through the policy, the approval
    /// queue, and the audit log, with `principal`. Refer to [`Dispatcher::revert`].
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`] if `principal` does not have the permission
    ///   `approve_actions`.
    /// - The errors of [`Dispatcher::revert`]: for example [`Error::NotFound`] if the
    ///   audit log has no execution of the action, and [`Error::InvalidInput`] if the
    ///   action was a dry run or was reverted before.
    pub async fn revert_action(
        &self,
        action_id: ActionId,
        principal: &Principal,
        reason: &str,
    ) -> Result<ActionDisposition> {
        self.rbac.check(principal, Permission::ApproveActions)?;
        let disposition = self.dispatcher.revert(action_id, principal, reason).await?;
        self.activity.bump();
        Ok(disposition)
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
