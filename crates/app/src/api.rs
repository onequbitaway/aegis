//! The operator API of the application: the REST API, the web console, and ChatOps.
//!
//! This module joins [`aegis_api`] to the services of one [`App`]. It is in the crate
//! only with the Cargo feature `api`.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`service`] | Makes the [`Service`] of the operator API for [`App::run_with`]. |
//! | [`OperatorApi`] | The API state from the services of the application, and the `[api]` section. |
//! | [`BoundApi`] | An [`OperatorApi`] with its listener. |
//! | [`AppApprovals`] | The approval path of the API. It calls the application. |
//! | [`AppReverts`] | The path of the API for timed reverts and for the revert of an action. |
//! | [`AppStatus`] | The data of the application for the status route: the flood counters. |
//!
//! # The services
//!
//! The API reads the incident store, the Defensive Graph, the audit log, the approval
//! queue, and the bus of the application. It checks each permission with the `[rbac]`
//! section of the application. It shows and drives the agent runtime of the application.
//!
//! # Fail closed
//!
//! - The module needs the `[api]` section. It has no default principal and no open mode.
//! - A principal with `token_env` must have that variable set. [`OperatorApi::check`]
//!   reads each secret before the server starts.
//! - A process that runs no agent has no operator API. [`OperatorApi::new`] is then an
//!   [`Error::Config`].
//!
//! # A request that goes away
//!
//! The API has a time limit for each request, and a client can close its connection.
//! The server then drops the work of the request. Three operations must not stop in the
//! middle, so they run in tasks of their own:
//!
//! - **A decision.** [`AppApprovals`] records the decision, runs the approved action, and
//!   gives the result to the agent in one task. The task completes also when the request
//!   is gone.
//! - **A revert.** [`AppReverts`] confirms, moves, or does a revert in one task.
//! - **One action of a playbook.** Each action of a playbook that the API starts goes
//!   through the dispatcher in one task. A request that goes away stops the playbook
//!   between two actions, never in the middle of one.
//!
//! When the server stops, [`BoundApi::serve`] waits for these tasks.
//!
//! # Playbooks
//!
//! `response.playbooks` is the limit for a playbook that the API starts:
//!
//! | `response.playbooks` | The API |
//! | --- | --- |
//! | `off` | Has no playbook. |
//! | `dry_run` | Lists the playbooks. Each run is a dry run, also when the request asks for `live`. |
//! | `live` | Lists the playbooks. The request selects the mode. |
//!
//! `response.dry_run` makes each action a dry run in all three modes.
//!
//! The API has the playbook set of the time when [`OperatorApi::new`] ran. It does not
//! see a later [`App::reload`].
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use aegis_app::{App, RunOptions, api};
//! use aegis_core::{Config, Shutdown};
//!
//! # async fn example() -> aegis_contracts::Result<()> {
//! let config = Config::load_with_env("aegis.toml")?;
//! let app = Arc::new(App::build(&config).await?);
//!
//! let shutdown = Shutdown::new();
//! shutdown.listen_for_signals()?;
//! let options = RunOptions {
//!     stop_when_sources_end: false,
//!     services: vec![api::service(&app).await?],
//! };
//! app.run_with(shutdown, options).await?;
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub use aegis_api::{
    ApiConfig, ApiParts, ApiState, ApprovalActions, ApprovalDecision, FloodStatus, RevertActions,
    StatusSource, SystemStatus,
};
use aegis_contracts::action::{ActionDispatcher, ActionDisposition, ActionRequest};
use aegis_contracts::common::{ActionId, ApprovalId};
use aegis_contracts::policy::Principal;
use aegis_contracts::{Error, Result};
use aegis_core::{Module, Shutdown};
use aegis_respond::{PendingRevert, PlaybookEngine};
use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio_util::task::TaskTracker;

use crate::app::{App, Service};
use crate::settings::{
    API_SECTION, PlaybookMode, api_needs_agents, api_section_missing, section_error,
};

/// The name of the service of the operator API in [`App::run_with`].
pub const SERVICE_NAME: &str = "api";

/// Runs work in tasks that complete also when the caller is gone.
#[derive(Clone, Default)]
struct Detached {
    tasks: TaskTracker,
}

impl Detached {
    /// Runs `work` in a task of its own and waits for the result.
    ///
    /// If the caller drops this function before it returns, the task continues to its
    /// end. `operation` names the work in the error for a task that did not complete.
    async fn run<T, F>(&self, operation: &'static str, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: Future<Output = Result<T>> + Send + 'static,
    {
        match self.tasks.spawn(work).await {
            Ok(result) => result,
            Err(error) => Err(Error::other(operation, error)),
        }
    }

    /// Waits until each task that started is complete.
    async fn settle(&self) {
        self.tasks.close();
        self.tasks.wait().await;
        // A later task must be able to start, and a later call must wait for it.
        self.tasks.reopen();
    }
}

/// The approval path of the operator API: an [`ApprovalActions`] that calls the
/// application.
///
/// A decision does the steps of [`App::decide_approval`]: the approval service checks the
/// permission and the approval rules, writes the audit record, and records the decision.
/// For an approval, the dispatcher then runs the action one time, and the agent that
/// proposed the action gets the result.
///
/// The steps run in a task of their own. The task completes also when the caller drops
/// [`ApprovalActions::decide`], for example at the time limit of an HTTP request. Thus a
/// decision is never half-applied.
///
/// # The answer after the record of the decision
///
/// After the approval service recorded the decision, the answer is always the decided
/// request. If the approved action did not run, the answer has a disposition with the
/// status `failed` and the cause. The API thus never answers with an error for a decision
/// that took effect.
pub struct AppApprovals {
    app: Arc<App>,
    work: Detached,
}

impl AppApprovals {
    /// Makes the approval path of `app`.
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        Self::with_work(app, Detached::default())
    }

    fn with_work(app: Arc<App>, work: Detached) -> Self {
        Self { app, work }
    }

    /// Waits until each decision that started is complete.
    pub async fn settle(&self) {
        self.work.settle().await;
    }
}

#[async_trait]
impl ApprovalActions for AppApprovals {
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> Result<ApprovalDecision> {
        let app = self.app.clone();
        let principal = principal.clone();
        self.work
            .run("complete the approval decision", async move {
                let decided = app.record_decision(id, approve, &principal, note).await?;
                if let Some(error) = &decided.failure {
                    // The caller gets the decided request. The cause must not be lost
                    // when the caller is gone.
                    tracing::error!(
                        approval = %id,
                        principal = %principal.id,
                        %error,
                        "the decision is recorded, but a later step failed"
                    );
                }
                Ok(ApprovalDecision {
                    request: decided.approval,
                    disposition: decided.disposition,
                })
            })
            .await
    }
}

/// The path of the operator API for timed reverts and for the revert of an action: a
/// [`RevertActions`] that calls the application.
///
/// Each operation checks the permission `approve_actions` of the principal again. The
/// revert scheduler and the dispatcher write each audit record with the principal. A
/// revert goes through the policy, the approval queue, and the audit log.
///
/// Each operation that changes state runs in a task of its own. The task completes also
/// when the caller drops the call, for example at the time limit of an HTTP request.
pub struct AppReverts {
    app: Arc<App>,
    work: Detached,
}

impl AppReverts {
    /// Makes the revert path of `app`.
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        Self::with_work(app, Detached::default())
    }

    fn with_work(app: Arc<App>, work: Detached) -> Self {
        Self { app, work }
    }

    /// Waits until each operation that started is complete.
    pub async fn settle(&self) {
        self.work.settle().await;
    }
}

#[async_trait]
impl RevertActions for AppReverts {
    fn enabled(&self) -> bool {
        self.app.revert_scheduler().is_some()
    }

    async fn pending(&self) -> Result<Vec<PendingRevert>> {
        self.app.pending_reverts().await
    }

    async fn confirm(&self, action_id: ActionId, principal: &Principal) -> Result<PendingRevert> {
        let (app, principal) = (self.app.clone(), principal.clone());
        self.work
            .run("complete the confirmation of an action", async move {
                app.confirm_revert(action_id, &principal).await
            })
            .await
    }

    async fn extend(
        &self,
        action_id: ActionId,
        principal: &Principal,
        extension: Duration,
    ) -> Result<PendingRevert> {
        let (app, principal) = (self.app.clone(), principal.clone());
        self.work
            .run("complete the change of a revert time", async move {
                app.extend_revert(action_id, &principal, extension).await
            })
            .await
    }

    async fn cancel(
        &self,
        action_id: ActionId,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        let (app, principal) = (self.app.clone(), principal.clone());
        self.work
            .run("complete the revert of an action", async move {
                app.cancel_revert(action_id, &principal).await
            })
            .await
    }

    async fn revert(
        &self,
        action_id: ActionId,
        principal: &Principal,
        reason: &str,
    ) -> Result<ActionDisposition> {
        let (app, principal, reason) = (self.app.clone(), principal.clone(), reason.to_owned());
        self.work
            .run("complete the revert of an action", async move {
                app.revert_action(action_id, &principal, &reason).await
            })
            .await
    }
}

/// The data of the application for the status route of the operator API.
///
/// | Field of the status document | Contents |
/// | --- | --- |
/// | `flood` | The counts of the flood protection of the detection engine. |
/// | `reverts` | `enabled`, the number of pending timed reverts, and the counts of the scheduler. |
/// | `evidence` | The counts of the evidence archive, if the archive is on. |
/// | `decoy` | The address and the counts of the decoy service, if it runs. |
pub struct AppStatus {
    app: Arc<App>,
}

impl AppStatus {
    /// Makes the status source of `app`.
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        Self { app }
    }
}

#[async_trait]
impl StatusSource for AppStatus {
    async fn status(&self) -> SystemStatus {
        let counters = self.app.flood_counters();
        SystemStatus {
            flood: FloodStatus {
                suppressed_matches: counters.suppressed_matches,
                repeat_detections: counters.repeat_detections,
                triage_quota_denials: counters.triage_quota_denials,
                coalesced_incident_updates: counters.coalesced_incident_updates,
            },
            sections: self.app.status_sections().await,
        }
    }
}

/// The dispatcher of the playbooks that the API starts.
///
/// It applies the playbook mode of the configuration, and it sends each request to the
/// dispatcher of the application in a task of its own.
struct ApiDispatcher {
    inner: Arc<dyn ActionDispatcher>,
    /// `false` if `response.playbooks` is not `live`. Each request is then a dry run.
    live: bool,
    work: Detached,
}

#[async_trait]
impl ActionDispatcher for ApiDispatcher {
    async fn dispatch(
        &self,
        mut request: ActionRequest,
        principal: &Principal,
    ) -> Result<ActionDisposition> {
        if !self.live {
            request.dry_run = true;
        }
        let inner = self.inner.clone();
        let principal = principal.clone();
        self.work
            .run("complete the action of a playbook", async move {
                inner.dispatch(request, &principal).await
            })
            .await
    }
}

/// Makes the playbook engine of the API from the active playbooks of the application.
fn playbook_engine(app: &App, work: &Detached) -> Result<Arc<PlaybookEngine>> {
    let playbooks = app.playbooks();
    let mode = playbooks.mode();
    let mut engine = PlaybookEngine::new(Arc::new(ApiDispatcher {
        inner: app.actions(),
        live: mode == PlaybookMode::Live,
        work: work.clone(),
    }));
    if mode != PlaybookMode::Off {
        for playbook in playbooks.engine().playbooks() {
            engine
                .add(playbook.clone())
                .map_err(|error| section_error("response", error))?;
        }
    }
    Ok(Arc::new(engine))
}

/// The operator API of one application: the API state and the `[api]` section.
///
/// [`OperatorApi::new`] connects the API to the services of the application. It opens no
/// socket and reads no secret. [`OperatorApi::bind`] reads the secrets and opens the
/// listener.
pub struct OperatorApi {
    config: ApiConfig,
    state: ApiState,
    work: Detached,
}

impl OperatorApi {
    /// Makes the operator API from the services of `app` and its `[api]` section.
    ///
    /// The API reads its secrets from the environment of the process. Use
    /// [`OperatorApi::with_env`] to give the values in a test.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the configuration has no `[api]` section, or if the
    /// application runs no agent.
    pub fn new(app: &Arc<App>) -> Result<Self> {
        let config = app.settings().api.clone().ok_or_else(api_section_missing)?;
        let agents = app.agents().ok_or_else(api_needs_agents)?;
        let work = Detached::default();
        let state = ApiState::new(ApiParts {
            incidents: app.incidents(),
            graph: app.graph(),
            audit: app.audit(),
            approvals: app.approvals(),
            bus: app.bus(),
            rbac: app.rbac().as_ref().clone(),
            agents,
            playbooks: playbook_engine(app, &work)?,
            approval_actions: Arc::new(AppApprovals::with_work(app.clone(), work.clone())),
            modules: app.modules().clone(),
        })
        .with_reverts(Arc::new(AppReverts::with_work(app.clone(), work.clone())))
        .with_status(Arc::new(AppStatus::new(app.clone())));
        Ok(Self {
            config,
            state,
            work,
        })
    }

    /// Sets the function that returns the value of an environment variable.
    ///
    /// The API calls it for each `*_env` name of the `[api]` section.
    #[must_use]
    pub fn with_env(
        mut self,
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.state = self.state.with_env(env);
        self
    }

    /// Returns the `[api]` section.
    #[must_use]
    pub fn config(&self) -> &ApiConfig {
        &self.config
    }

    /// Returns the state of the API. Use it with `aegis_api::router` to make a router
    /// with no server.
    #[must_use]
    pub fn state(&self) -> &ApiState {
        &self.state
    }

    /// Checks the `[api]` section with its secrets. Opens no socket and starts no task.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a value is not valid, or if an environment variable
    /// that the section names is not set or holds a value that is not usable. The message
    /// names the section and the variable. It never shows a secret.
    pub fn check(&self) -> Result<()> {
        aegis_api::router(self.state.clone(), &self.config)
            .map(|_| ())
            .map_err(|error| section_error(API_SECTION, error))
    }

    /// Checks the section and opens the listener on `api.bind`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`OperatorApi::check`]. Returns [`Error::Unavailable`] if the
    /// operating system refuses the address.
    pub async fn bind(self) -> Result<BoundApi> {
        self.check()?;
        let address = self.config.bind;
        let listener = TcpListener::bind(address).await.map_err(|error| {
            section_error(
                API_SECTION,
                Error::Unavailable(format!(
                    "the operator API cannot listen on {address}: {error}"
                )),
            )
        })?;
        self.bound(listener)
    }

    /// Checks the section and uses a listener that the caller made.
    ///
    /// Use this function to listen on a port that the operating system selects, for
    /// example in a test. `api.bind` is not used.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`OperatorApi::check`].
    pub fn on_listener(self, listener: TcpListener) -> Result<BoundApi> {
        self.check()?;
        self.bound(listener)
    }

    fn bound(self, listener: TcpListener) -> Result<BoundApi> {
        let address = listener.local_addr().map_err(|error| {
            section_error(
                API_SECTION,
                Error::other("read the address of the listener", error),
            )
        })?;
        Ok(BoundApi {
            api: self,
            listener,
            address,
        })
    }

    /// Waits until each decision and each playbook action that started is complete.
    pub async fn settle(&self) {
        self.work.settle().await;
    }
}

/// An [`OperatorApi`] with its listener. The server does not answer before
/// [`BoundApi::serve`] runs.
pub struct BoundApi {
    api: OperatorApi,
    listener: TcpListener,
    address: SocketAddr,
}

impl BoundApi {
    /// Returns the address of the listener.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Returns the operator API of this listener.
    #[must_use]
    pub fn api(&self) -> &OperatorApi {
        &self.api
    }

    /// Runs the server until `shutdown` is triggered.
    ///
    /// After the signal, the server stops to accept connections, ends each live feed, and
    /// lets each open request complete. The function then waits for each decision and
    /// each playbook action whose request went away.
    ///
    /// # Errors
    ///
    /// Returns the error of the server. The message names the section `api`.
    pub async fn serve(self, shutdown: Shutdown) -> Result<()> {
        let Self {
            api,
            listener,
            address,
        } = self;
        tracing::info!(%address, "the operator API listens");
        let served = aegis_api::serve_on(listener, api.state, api.config, shutdown).await;
        api.work.settle().await;
        tracing::info!(%address, "the operator API stopped");
        served.map_err(|error| section_error(API_SECTION, error))
    }

    /// Makes the service of the module `api` for [`App::run_with`].
    ///
    /// The application starts the service only if the module `api` is in the module set.
    /// If the server fails, the application stops all components.
    #[must_use]
    pub fn into_service(self) -> Service {
        Service::new(SERVICE_NAME, move |shutdown| self.serve(shutdown)).for_module(Module::Api)
    }
}

/// Makes the service of the operator API of `app` for [`App::run_with`].
///
/// The function checks the `[api]` section with its secrets and opens the listener on
/// `api.bind`. Thus a configuration that is not usable stops the program before the
/// application starts its sources.
///
/// # Errors
///
/// Returns the errors of [`OperatorApi::new`] and [`OperatorApi::bind`].
pub async fn service(app: &Arc<App>) -> Result<Service> {
    Ok(OperatorApi::new(app)?.bind().await?.into_service())
}
