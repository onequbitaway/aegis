//! The agent runtime: the task queue, the guard rails, and the path from an agent output
//! to the stores, the dispatcher, the audit log, and the bus.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use aegis_contracts::action::{ActionDispatcher, ActionRequest};
use aegis_contracts::audit::{AuditEntry, AuditKind};
use aegis_contracts::bus::{BusMessage, publish_json, subject};
use aegis_contracts::common::{EvidenceKind, EvidenceRef, IncidentId, TaskId};
use aegis_contracts::graph::NodeId;
use aegis_contracts::incident::Incident;
use aegis_contracts::policy::{Principal, PrincipalKind};
use aegis_contracts::{
    Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask, Error, Result,
};
use chrono::Utc;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Notify;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::agents::{Roster, built_in};
use crate::config::{BUILT_IN_ROLES, RuntimeConfig};
use crate::ledger::kind_token;
use crate::support::{self, one_line, token};

/// The actor name of the runtime in the audit log.
pub const RUNTIME_ACTOR: &str = "runtime";
const HISTORY_LIMIT: usize = 1024;
const MAX_NOTES_PER_TASK: usize = 64;
const MAX_EVIDENCE_PER_RECORD: usize = 64;
/// The number of bus errors in sequence on one subscription that stops [`AgentRuntime::run`].
const MAX_BUS_ERRORS_IN_SEQUENCE: u32 = 16;
const ABANDONED: &str = "the runtime stopped before the task completed";
/// The roles that can take an incident from the bus, in the order of preference.
const INTAKE_ROLES: [AgentRole; 3] = [
    AgentRole::Supervisor,
    AgentRole::Monitor,
    AgentRole::Analyst,
];

/// The state of the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    /// No function drives the queue.
    Idle,
    /// [`AgentRuntime::run`] or [`AgentRuntime::run_until_idle`] drives the queue.
    Running,
}

/// The state of one task.
///
/// A task starts as `Queued`. It becomes `Running` when an agent takes it. It ends as
/// `Completed` or `Failed`. A task that a guard rail stops is `Rejected` and never runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// The task waits in the queue.
    Queued,
    /// An agent works on the task.
    Running,
    /// The agent returned an output, and the runtime applied it.
    Completed,
    /// The agent returned an error, or the runtime could not apply the output.
    Failed,
    /// A guard rail stopped the task before an agent took it.
    Rejected,
}

/// The record of one task that ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRecord {
    /// The identifier of the task.
    pub id: TaskId,
    /// The role that the task was for.
    pub role: AgentRole,
    /// The incident of the task.
    pub incident_id: Option<IncidentId>,
    /// The length of the chain of tasks before this task. An external input has 0.
    pub depth: u64,
    /// The end state: `Completed`, `Failed`, or `Rejected`.
    pub state: TaskState,
    /// Why the task failed or why a guard rail stopped it.
    pub detail: Option<String>,
}

/// Counts of the work of the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RunReport {
    /// The number of tasks that completed.
    pub tasks_completed: u64,
    /// The number of tasks that failed.
    pub tasks_failed: u64,
    /// The number of tasks and bus messages that the runtime rejected.
    pub tasks_rejected: u64,
    /// The number of actions that the dispatcher took.
    pub actions_dispatched: u64,
    /// The number of proposed actions that the runtime did not send to the dispatcher.
    pub actions_rejected: u64,
    /// The number of actions for which the dispatcher returned an error.
    pub dispatch_failures: u64,
    /// The number of audit records that the audit log did not take.
    pub audit_failures: u64,
}

impl RunReport {
    /// Returns the counts of the work after `earlier`.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            tasks_completed: self.tasks_completed.saturating_sub(earlier.tasks_completed),
            tasks_failed: self.tasks_failed.saturating_sub(earlier.tasks_failed),
            tasks_rejected: self.tasks_rejected.saturating_sub(earlier.tasks_rejected),
            actions_dispatched: self
                .actions_dispatched
                .saturating_sub(earlier.actions_dispatched),
            actions_rejected: self
                .actions_rejected
                .saturating_sub(earlier.actions_rejected),
            dispatch_failures: self
                .dispatch_failures
                .saturating_sub(earlier.dispatch_failures),
            audit_failures: self.audit_failures.saturating_sub(earlier.audit_failures),
        }
    }
}

/// Why the runtime did not accept a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Rejection {
    NoAgent,
    DepthLimit,
    StepLimit,
    QueueFull,
}

impl Rejection {
    fn reason(self) -> &'static str {
        match self {
            Self::NoAgent => "no enabled agent has this role",
            Self::DepthLimit => "the chain of tasks is longer than limits.max_task_depth",
            Self::StepLimit => {
                "the incident has more tasks from one input than limits.max_steps_per_incident"
            }
            Self::QueueFull => "the queue holds limits.max_queued_tasks tasks",
        }
    }
}

struct Queued {
    task: AgentTask,
    depth: u64,
    root: TaskId,
}

/// The data of a task that the runtime keeps after the agent takes the task.
struct TaskMeta {
    ticket: u64,
    id: TaskId,
    role: AgentRole,
    incident_id: Option<IncidentId>,
    depth: u64,
    root: TaskId,
    input: &'static str,
    evidence: Vec<EvidenceRef>,
}

/// The data of a running task that the queue needs when the task ends.
struct RunningTask {
    id: TaskId,
    role: AgentRole,
    incident_id: Option<IncidentId>,
    depth: u64,
    root: TaskId,
    is_root_tick: bool,
}

/// The two bus subscriptions of [`AgentRuntime::run`].
#[derive(Clone, Copy)]
enum Intake {
    Tasks,
    Incidents,
}

impl Intake {
    fn subject(self) -> &'static str {
        match self {
            Self::Tasks => subject::AGENT_TASKS,
            Self::Incidents => subject::INCIDENTS,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Tasks => "agent tasks",
            Self::Incidents => "incidents",
        }
    }
}

/// The step counts of all tasks that one external input caused.
#[derive(Default)]
struct RootBudget {
    live: usize,
    steps: HashMap<Option<IncidentId>, u64>,
}

#[derive(Default)]
struct Inner {
    queue: VecDeque<Queued>,
    /// The running tasks. The key is a number that the runtime gives to each start of a
    /// task, so that two tasks with the same identifier do not share one entry.
    running: HashMap<u64, RunningTask>,
    next_ticket: u64,
    busy_incidents: HashSet<IncidentId>,
    roots: HashMap<TaskId, RootBudget>,
    pending_ticks: HashSet<AgentRole>,
    history: VecDeque<TaskRecord>,
    stats: RunReport,
    driving: bool,
}

type StepFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Makes an [`AgentRuntime`].
pub struct AgentRuntimeBuilder {
    context: AgentContext,
    dispatcher: Arc<dyn ActionDispatcher>,
    config: RuntimeConfig,
    use_built_in: bool,
    custom: Vec<Arc<dyn Agent>>,
}

impl AgentRuntimeBuilder {
    /// Sets the configuration. The default is [`RuntimeConfig::default`], which is a dry
    /// run.
    #[must_use]
    pub fn config(mut self, config: RuntimeConfig) -> Self {
        self.config = config;
        self
    }

    /// Adds the built-in agent for each enabled built-in role.
    #[must_use]
    pub fn with_default_agents(mut self) -> Self {
        self.use_built_in = true;
        self
    }

    /// Adds an agent. It replaces the built-in agent with the same role.
    ///
    /// The runtime ignores an agent whose role is not in
    /// [`RuntimeConfig::enabled_roles`].
    #[must_use]
    pub fn agent(mut self, agent: Arc<dyn Agent>) -> Self {
        self.custom.push(agent);
        self
    }

    /// Checks the configuration and makes the runtime.
    ///
    /// A configuration that is not valid, or a runtime with no enabled agent, gives
    /// [`Error::Config`].
    pub fn build(self) -> Result<AgentRuntime> {
        self.config.validate()?;
        let enabled = self.config.enabled();
        let mut agents: BTreeMap<AgentRole, Arc<dyn Agent>> = BTreeMap::new();
        for agent in self.custom {
            let role = agent.role();
            if enabled.contains(&role) {
                agents.insert(role, agent);
            } else {
                tracing::info!(
                    role = role.token(),
                    "ignored an agent for a role that is not enabled"
                );
            }
        }
        let mut roles: Vec<AgentRole> = agents.keys().cloned().collect();
        if self.use_built_in {
            roles.extend(
                BUILT_IN_ROLES
                    .into_iter()
                    .filter(|role| enabled.contains(role)),
            );
        }
        let roster = Roster::new(roles);
        if self.use_built_in {
            for role in BUILT_IN_ROLES {
                if roster.has(&role)
                    && !agents.contains_key(&role)
                    && let Some(agent) = built_in(&role, &self.config, &roster)
                {
                    agents.insert(role, agent);
                }
            }
        }
        if agents.is_empty() {
            return Err(Error::Config(
                "the runtime has no enabled agent: add agents and check enabled_roles".to_owned(),
            ));
        }
        Ok(AgentRuntime {
            agents,
            roster,
            context: self.context,
            dispatcher: self.dispatcher,
            config: self.config,
            inner: Mutex::default(),
            wake: Notify::new(),
        })
    }
}

/// The orchestrator of the agents.
///
/// The runtime holds the agents, a task queue, and the guard rails. An agent returns an
/// [`AgentOutput`]. The runtime then does these steps in this order:
///
/// 1. It writes each changed incident to the incident store.
/// 2. It writes each note and each decision to the audit log.
/// 3. It sends each proposed action to the [`ActionDispatcher`], with a principal for the
///    agent. It gives the result back to the agent as a new task.
/// 4. It puts the new tasks in the queue.
///
/// An agent never changes the environment. Only the dispatcher can do that, under the
/// policy of the operator.
///
/// # Guard rails
///
/// - Tasks for one incident run one at a time, in the order of the queue.
/// - At most [`max_concurrency`](crate::config::RuntimeLimits::max_concurrency) tasks run
///   at the same time.
/// - One external input can cause only
///   [`max_steps_per_incident`](crate::config::RuntimeLimits::max_steps_per_incident)
///   tasks for one incident, and a chain of tasks can have only
///   [`max_task_depth`](crate::config::RuntimeLimits::max_task_depth) links.
/// - An action that has no place for its result task is not dispatched.
/// - An action whose decision record the audit log does not take is not dispatched.
/// - An agent error, a panic, or a timeout goes to the audit log. The runtime continues.
/// - A dispatcher that does not answer in
///   [`task_timeout_seconds`](crate::config::RuntimeLimits::task_timeout_seconds) is a
///   dispatch failure. The agent gets a note, and the incident is free for its next task.
///
/// # Incidents
///
/// A task with the input [`AgentInput::Incident`] always belongs to that incident. Give
/// each other task for an incident its
/// [`incident_id`](aegis_contracts::AgentTask::incident_id), so that it waits for the
/// other tasks of the incident.
///
/// # Result tasks
///
/// The task with the result of an action has the same UUID as the action request. An
/// agent uses this to find the action of a denial or a pending approval, because these
/// results hold no action identifier.
pub struct AgentRuntime {
    agents: BTreeMap<AgentRole, Arc<dyn Agent>>,
    roster: Roster,
    context: AgentContext,
    dispatcher: Arc<dyn ActionDispatcher>,
    config: RuntimeConfig,
    inner: Mutex<Inner>,
    wake: Notify,
}

/// Sets the runtime back to idle when the function that drives the queue ends.
///
/// If the caller drops the function before it returns, the tasks that run stop with it.
/// The guard then frees their incidents and their places in the step counts, so that a
/// later call can work on the same incidents.
struct DriverGuard<'a>(&'a AgentRuntime);

impl Drop for DriverGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.0.lock();
        let inner = &mut *guard;
        inner.driving = false;
        if inner.running.is_empty() {
            return;
        }
        let mut abandoned: Vec<(u64, RunningTask)> = inner.running.drain().collect();
        abandoned.sort_by_key(|(ticket, _)| *ticket);
        for (_, task) in abandoned {
            tracing::warn!(
                role = task.role.token(),
                task = %task.id,
                "the runtime stopped before a task completed"
            );
            release(inner, task, TaskState::Failed, Some(ABANDONED.to_owned()));
        }
        // No task runs now. Each place in a step count is thus a task in the queue.
        for budget in inner.roots.values_mut() {
            budget.live = 0;
        }
        for queued in &inner.queue {
            if let Some(budget) = inner.roots.get_mut(&queued.root) {
                budget.live += 1;
            }
        }
        inner.roots.retain(|_, budget| budget.live > 0);
    }
}

impl AgentRuntime {
    /// Starts a builder. `context` holds the shared services. `dispatcher` is the single
    /// path for proposed actions.
    #[must_use]
    pub fn builder(
        context: AgentContext,
        dispatcher: Arc<dyn ActionDispatcher>,
    ) -> AgentRuntimeBuilder {
        AgentRuntimeBuilder {
            context,
            dispatcher,
            config: RuntimeConfig::default(),
            use_built_in: false,
            custom: Vec::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Returns the roles that can receive tasks.
    #[must_use]
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// Returns the state of the runtime.
    #[must_use]
    pub fn state(&self) -> RuntimeState {
        if self.lock().driving {
            RuntimeState::Running
        } else {
            RuntimeState::Idle
        }
    }

    /// Returns the counts of all work since the runtime was made.
    #[must_use]
    pub fn stats(&self) -> RunReport {
        self.lock().stats
    }

    /// Returns the number of tasks that wait in the queue.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.lock().queue.len()
    }

    /// Returns `true` if no task waits and no task runs.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        let inner = self.lock();
        inner.queue.is_empty() && inner.running.is_empty()
    }

    /// Returns the records of the last tasks that ended, oldest first.
    #[must_use]
    pub fn recent_tasks(&self) -> Vec<TaskRecord> {
        self.lock().history.iter().cloned().collect()
    }

    /// Returns the state of a task. `None` means that the runtime does not know the task
    /// or that the record of the task is too old.
    #[must_use]
    pub fn task_state(&self, id: TaskId) -> Option<TaskState> {
        let inner = self.lock();
        if inner.running.values().any(|running| running.id == id) {
            return Some(TaskState::Running);
        }
        if inner.queue.iter().any(|queued| queued.task.id == id) {
            return Some(TaskState::Queued);
        }
        inner
            .history
            .iter()
            .rev()
            .find(|record| record.id == id)
            .map(|record| record.state)
    }

    /// Puts an external task in the queue.
    ///
    /// The task is the start of a new chain: it has the depth 0 and a new step count. A
    /// task for a role with no enabled agent gives [`Error::InvalidInput`]. A full queue
    /// gives [`Error::Unavailable`].
    pub fn submit(&self, task: AgentTask) -> Result<()> {
        let root = task.id;
        let role = task.to.clone();
        match self.enqueue(task, 0, root) {
            Ok(()) => {
                self.wake.notify_one();
                Ok(())
            }
            Err(Rejection::NoAgent) => Err(Error::InvalidInput(format!(
                "no enabled agent has the role {}",
                one_line(role.token())
            ))),
            Err(Rejection::QueueFull) => {
                Err(Error::Unavailable("the task queue is full".to_owned()))
            }
            Err(rejection @ (Rejection::DepthLimit | Rejection::StepLimit)) => {
                Err(Error::BudgetExceeded(rejection.reason().to_owned()))
            }
        }
    }

    /// Puts the goal of the operator in the queue as a task for the Supervisor.
    pub fn submit_goal(&self, goal: impl Into<String>) -> Result<TaskId> {
        let task = AgentTask::new(AgentRole::Supervisor, AgentInput::Goal(goal.into()));
        let id = task.id;
        self.submit(task)?;
        Ok(id)
    }

    /// Puts an incident in the queue. The first enabled role of Supervisor, Monitor, and
    /// Analyst gets the task.
    ///
    /// If none of these roles has an enabled agent, the function gives
    /// [`Error::InvalidInput`]. The other errors are the errors of [`Self::submit`].
    pub fn submit_incident(&self, incident: Incident) -> Result<TaskId> {
        let Some(role) = INTAKE_ROLES
            .into_iter()
            .find(|role| self.agents.contains_key(role))
        else {
            self.count(|stats| stats.tasks_rejected += 1);
            return Err(Error::InvalidInput(
                "no enabled agent can take an incident: enable the supervisor, the monitor, \
                 or the analyst"
                    .to_owned(),
            ));
        };
        let incident_id = incident.id;
        let task = AgentTask::new(role, AgentInput::Incident(Box::new(incident)))
            .for_incident(incident_id);
        let id = task.id;
        self.submit(task)?;
        Ok(id)
    }

    /// Runs tasks until the queue is empty and no task runs.
    ///
    /// The function returns the counts of its work. An agent error does not stop it. A
    /// second call while the runtime runs gives [`Error::InvalidInput`].
    ///
    /// If the caller drops this function before it returns, the tasks that run stop
    /// without a result. Their records have the state [`TaskState::Failed`].
    pub async fn run_until_idle(&self) -> Result<RunReport> {
        let _guard = self.begin()?;
        let before = self.stats();
        let mut in_flight: FuturesUnordered<StepFuture<'_>> = FuturesUnordered::new();
        loop {
            self.fill(&mut in_flight);
            if in_flight.next().await.is_none() {
                break;
            }
        }
        Ok(self.stats().since(&before))
    }

    /// Runs until `cancellation` is cancelled.
    ///
    /// The function takes tasks from the bus subjects `aegis.agents.tasks.{role}` and
    /// incidents from `aegis.incidents`. It sends a `Tick` task to each agent at the
    /// configured interval. After the cancellation, it completes the tasks that run and
    /// returns the counts of its work. Tasks that wait stay in the queue.
    ///
    /// The subject of a task message must be `aegis.agents.tasks.{role}` for the role in
    /// the task. The runtime discards a message that it cannot use and writes the reason
    /// to the audit log.
    ///
    /// A bus subscription that ends gives [`Error::Unavailable`]. A subscription that
    /// gives 16 errors in sequence gives the same error.
    pub async fn run(&self, cancellation: CancellationToken) -> Result<RunReport> {
        let _guard = self.begin()?;
        let before = self.stats();
        let consumer = |suffix: &str| {
            self.config
                .bus_consumer
                .as_ref()
                .map(|name| format!("{name}-{suffix}"))
        };
        let bus = self.context.bus.as_ref();
        let mut tasks = bus
            .subscribe(
                &format!("{}.>", subject::AGENT_TASKS),
                consumer("tasks").as_deref(),
            )
            .await?;
        let mut incidents = bus
            .subscribe(subject::INCIDENTS, consumer("incidents").as_deref())
            .await?;
        let mut ticker = self.config.tick_interval().and_then(|period| {
            let first = Instant::now().checked_add(period)?;
            let mut interval = tokio::time::interval_at(first, period);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            Some(interval)
        });
        let max_queued = to_usize(self.config.limits.max_queued_tasks);
        let mut in_flight: FuturesUnordered<StepFuture<'_>> = FuturesUnordered::new();
        let mut task_errors = 0_u32;
        let mut incident_errors = 0_u32;
        let mut failure = None;
        loop {
            // After the cancellation, no new task starts.
            if cancellation.is_cancelled() {
                break;
            }
            self.fill(&mut in_flight);
            let has_room = self.queued() < max_queued;
            // The order of the checks is random, so that a flood on one subscription
            // does not stop the other subscription or the `Tick` tasks.
            tokio::select! {
                () = cancellation.cancelled() => break,
                Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
                item = tasks.next(), if has_room => {
                    if let Err(error) = self.intake(Intake::Tasks, item, &mut task_errors).await {
                        failure = Some(error);
                        break;
                    }
                }
                item = incidents.next(), if has_room => {
                    let taken = self
                        .intake(Intake::Incidents, item, &mut incident_errors)
                        .await;
                    if let Err(error) = taken {
                        failure = Some(error);
                        break;
                    }
                }
                () = next_tick(&mut ticker) => self.enqueue_ticks(),
                () = self.wake.notified() => {}
            }
        }
        while in_flight.next().await.is_some() {}
        match failure {
            Some(error) => Err(error),
            None => Ok(self.stats().since(&before)),
        }
    }

    fn begin(&self) -> Result<DriverGuard<'_>> {
        let mut inner = self.lock();
        if inner.driving {
            return Err(Error::InvalidInput(
                "the runtime already runs: wait for run or run_until_idle to return".to_owned(),
            ));
        }
        inner.driving = true;
        Ok(DriverGuard(self))
    }

    /// Starts tasks until the concurrency limit is reached or no task is ready.
    fn fill<'a>(&'a self, in_flight: &mut FuturesUnordered<StepFuture<'a>>) {
        let limit = to_usize(self.config.limits.max_concurrency);
        while in_flight.len() < limit {
            match self.next_ready() {
                Some((ticket, queued)) => in_flight.push(Box::pin(self.step(ticket, queued))),
                None => break,
            }
        }
    }

    /// Takes the first task in the queue whose incident has no running task.
    fn next_ready(&self) -> Option<(u64, Queued)> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let position = inner.queue.iter().position(|queued| {
            queued
                .task
                .incident_id
                .is_none_or(|id| !inner.busy_incidents.contains(&id))
        })?;
        let queued = inner.queue.remove(position)?;
        if let Some(id) = queued.task.incident_id {
            inner.busy_incidents.insert(id);
        }
        inner.next_ticket = inner.next_ticket.wrapping_add(1);
        let ticket = inner.next_ticket;
        inner.running.insert(
            ticket,
            RunningTask {
                id: queued.task.id,
                role: queued.task.to.clone(),
                incident_id: queued.task.incident_id,
                depth: queued.depth,
                root: queued.root,
                is_root_tick: queued.depth == 0 && matches!(queued.task.input, AgentInput::Tick),
            },
        );
        Some((ticket, queued))
    }

    /// Counts a task against the guard rails. The caller then puts the task in the queue.
    fn admit(
        &self,
        inner: &mut Inner,
        role: &AgentRole,
        incident_id: Option<IncidentId>,
        depth: u64,
        root: TaskId,
    ) -> std::result::Result<(), Rejection> {
        let limits = &self.config.limits;
        if !self.agents.contains_key(role) {
            return Err(Rejection::NoAgent);
        }
        if depth > limits.max_task_depth {
            return Err(Rejection::DepthLimit);
        }
        if inner.queue.len() >= to_usize(limits.max_queued_tasks) {
            return Err(Rejection::QueueFull);
        }
        let budget = inner.roots.entry(root).or_default();
        let steps = budget.steps.entry(incident_id).or_insert(0);
        if *steps >= limits.max_steps_per_incident {
            return Err(Rejection::StepLimit);
        }
        *steps += 1;
        budget.live += 1;
        Ok(())
    }

    fn enqueue(
        &self,
        mut task: AgentTask,
        depth: u64,
        root: TaskId,
    ) -> std::result::Result<(), Rejection> {
        // The incident in the input is the incident of the task. The agent changes that
        // incident, so the task must wait for the other tasks of that incident.
        if let AgentInput::Incident(incident) = &task.input {
            task.incident_id = Some(incident.id);
        }
        let mut inner = self.lock();
        match self.admit(&mut inner, &task.to, task.incident_id, depth, root) {
            Ok(()) => {
                inner.queue.push_back(Queued { task, depth, root });
                Ok(())
            }
            Err(rejection) => {
                inner.stats.tasks_rejected += 1;
                push_history(
                    &mut inner,
                    TaskRecord {
                        id: task.id,
                        role: task.to,
                        incident_id: task.incident_id,
                        depth,
                        state: TaskState::Rejected,
                        detail: Some(rejection.reason().to_owned()),
                    },
                );
                Err(rejection)
            }
        }
    }

    fn count(&self, change: impl FnOnce(&mut RunReport)) {
        change(&mut self.lock().stats);
    }

    /// Writes one record to the audit log. Returns `false` if the log did not take it.
    async fn audit(&self, entry: AuditEntry) -> bool {
        match self.context.audit.append(entry).await {
            Ok(_) => true,
            Err(error) => {
                tracing::error!(error = %error, "the audit log did not take a record");
                self.count(|stats| stats.audit_failures += 1);
                false
            }
        }
    }

    /// Runs one task and applies its output.
    async fn step(&self, ticket: u64, queued: Queued) {
        let Queued { task, depth, root } = queued;
        let meta = TaskMeta {
            ticket,
            id: task.id,
            role: task.to.clone(),
            incident_id: task.incident_id,
            depth,
            root,
            input: input_kind(&task.input),
            evidence: task_evidence(&task),
        };
        let seconds = self.config.limits.task_timeout_seconds;
        let handled = match self.agents.get(&task.to) {
            Some(agent) => {
                let work = AssertUnwindSafe(agent.handle(task, &self.context)).catch_unwind();
                match tokio::time::timeout(Duration::from_secs(seconds), work).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(_)) => Err(Error::other("agent task", "the agent panicked")),
                    Err(_) => Err(Error::Timeout(format!(
                        "the task did not complete in {seconds} seconds"
                    ))),
                }
            }
            None => Err(Error::NotFound(format!(
                "an agent with the role {}",
                meta.role.token()
            ))),
        };
        let applied = match handled {
            Ok(output) => self.apply(&meta, output).await,
            Err(error) => Err(error),
        };
        let (state, detail) = match applied {
            Ok(()) => (TaskState::Completed, None),
            Err(error) => {
                let detail = one_line(&error.to_string());
                tracing::warn!(
                    role = meta.role.token(),
                    task = %meta.id,
                    error = %detail,
                    "an agent task failed"
                );
                let entry = AuditEntry::new(
                    AuditKind::Other,
                    meta.role.token(),
                    format!(
                        "The {} agent failed on the task {}: {detail}",
                        meta.role.token(),
                        meta.id
                    ),
                )
                .with_payload(json!({
                    "task_id": meta.id,
                    "incident_id": meta.incident_id,
                    "input": meta.input,
                    "retryable": error.is_retryable(),
                }))
                .with_evidence(meta.evidence.clone());
                self.audit(entry).await;
                (TaskState::Failed, Some(detail))
            }
        };
        self.finish(&meta, state, detail);
    }

    /// Records the end of a task and frees its incident for the next task.
    fn finish(&self, meta: &TaskMeta, state: TaskState, detail: Option<String>) {
        let mut inner = self.lock();
        if let Some(task) = inner.running.remove(&meta.ticket) {
            release(&mut inner, task, state, detail);
        }
    }

    /// Applies the output of an agent. An error means that the runtime could not write an
    /// incident. In that case the runtime dispatches no action of the output.
    async fn apply(&self, meta: &TaskMeta, output: AgentOutput) -> Result<()> {
        let actor = meta.role.token();
        let mut evidence = meta.evidence.clone();

        for incident in &output.incidents {
            let previous = self.context.incidents.get(incident.id).await?;
            self.context.incidents.save(incident).await?;
            let link = EvidenceRef::new(EvidenceKind::Incident, incident.id);
            if !evidence.contains(&link) {
                evidence.push(link);
            }
            let old = previous.map(|stored| stored.status);
            if old != Some(incident.status) {
                let from = old.map_or_else(|| "no state".to_owned(), |status| token(&status));
                let entry = AuditEntry::new(
                    AuditKind::AgentDecision,
                    actor,
                    format!(
                        "The {actor} agent changed the incident {} from {from} to {}.",
                        incident.id,
                        token(&incident.status)
                    ),
                )
                .with_payload(json!({
                    "task_id": meta.id,
                    "incident_id": incident.id,
                    "from": old,
                    "to": incident.status,
                }))
                .with_evidence(support::evidence(incident));
                self.audit(entry).await;
            }
        }
        evidence.truncate(MAX_EVIDENCE_PER_RECORD);

        for note in output.notes.iter().take(MAX_NOTES_PER_TASK) {
            let entry = AuditEntry::new(AuditKind::AgentDecision, actor, one_line(note))
                .with_payload(json!({
                    "task_id": meta.id,
                    "incident_id": meta.incident_id,
                    "input": meta.input,
                }))
                .with_evidence(evidence.clone());
            self.audit(entry).await;
        }
        if output.notes.len() > MAX_NOTES_PER_TASK {
            let entry = AuditEntry::new(
                AuditKind::Other,
                RUNTIME_ACTOR,
                format!(
                    "The runtime dropped {} notes of the {actor} agent for the task {}: the \
                     limit is {MAX_NOTES_PER_TASK} notes for one task.",
                    output.notes.len() - MAX_NOTES_PER_TASK,
                    meta.id
                ),
            );
            self.audit(entry).await;
        }

        self.dispatch_actions(meta, output.actions).await;
        self.queue_tasks(meta, output.tasks).await;
        Ok(())
    }

    /// Sends the proposed actions of one task to the dispatcher and queues the results.
    async fn dispatch_actions(&self, meta: &TaskMeta, actions: Vec<ActionRequest>) {
        let actor = meta.role.token();
        let principal = Principal::new(actor, PrincipalKind::Agent, &[actor]);
        let limit = to_usize(self.config.limits.max_actions_per_task);
        let mut rejected: BTreeMap<&'static str, u64> = BTreeMap::new();
        for (index, mut request) in actions.into_iter().enumerate() {
            if index >= limit {
                *rejected
                    .entry("the task has more actions than limits.max_actions_per_task")
                    .or_default() += 1;
                continue;
            }
            // The runtime knows which agent made the output. The agent cannot name a
            // different requester, and it cannot switch off the dry run.
            request.requested_by = actor.to_owned();
            request.dry_run = request.dry_run || self.config.dry_run;
            if request.incident_id.is_none() {
                request.incident_id = meta.incident_id;
            }
            let target = NodeId::for_entity(&request.target);
            let kind = kind_token(&request.kind);

            let mut links = request.evidence.clone();
            links.truncate(MAX_EVIDENCE_PER_RECORD);
            links.push(EvidenceRef::new(EvidenceKind::Action, request.id));
            let decision = AuditEntry::new(
                AuditKind::AgentDecision,
                actor,
                one_line(&format!(
                    "The {actor} agent proposed {kind} on {target}: {}",
                    request.reason
                )),
            )
            .with_payload(json!({
                "task_id": meta.id,
                "action_id": request.id,
                "incident_id": request.incident_id,
                "kind": request.kind,
                "target": target,
                "dry_run": request.dry_run,
            }))
            .with_evidence(links);
            // Fail closed: no action without the record of its decision.
            if !self.audit(decision).await {
                *rejected
                    .entry("the audit log did not take the decision record")
                    .or_default() += 1;
                continue;
            }

            // Keep a place for the result task before the action runs. This stops a loop
            // of actions and results at the step limit.
            let reserved = {
                let mut inner = self.lock();
                self.admit(
                    &mut inner,
                    &meta.role,
                    request.incident_id,
                    meta.depth + 1,
                    meta.root,
                )
            };
            if let Err(rejection) = reserved {
                *rejected.entry(rejection.reason()).or_default() += 1;
                continue;
            }

            self.publish(subject::ACTION_REQUESTS, &request).await;
            // A dispatcher that does not answer must not hold the incident forever.
            let seconds = self.config.limits.task_timeout_seconds;
            let dispatch = self.dispatcher.dispatch(request.clone(), &principal);
            let dispatched =
                match tokio::time::timeout(Duration::from_secs(seconds), dispatch).await {
                    Ok(result) => result,
                    Err(_) => Err(Error::Timeout(format!(
                        "the dispatcher did not answer in {seconds} seconds"
                    ))),
                };
            let input = match dispatched {
                Ok(disposition) => {
                    self.count(|stats| stats.actions_dispatched += 1);
                    // The dispatcher is the single publisher of `aegis.actions.results`.
                    // The runtime only gives the result back to the agent.
                    AgentInput::ActionResult(Box::new(disposition))
                }
                Err(error) => {
                    let detail = one_line(&error.to_string());
                    self.count(|stats| stats.dispatch_failures += 1);
                    tracing::warn!(action = %request.id, error = %detail, "a dispatch failed");
                    let entry = AuditEntry::new(
                        AuditKind::Other,
                        RUNTIME_ACTOR,
                        format!(
                            "The dispatcher did not take the action {} ({kind} on {target}): \
                             {detail}",
                            request.id
                        ),
                    )
                    .with_payload(json!({
                        "task_id": meta.id,
                        "action_id": request.id,
                        "incident_id": request.incident_id,
                        "retryable": error.is_retryable(),
                    }))
                    .with_evidence(vec![EvidenceRef::new(EvidenceKind::Action, request.id)]);
                    self.audit(entry).await;
                    AgentInput::Note(format!("The dispatcher did not take the action: {detail}"))
                }
            };
            let result = AgentTask {
                id: TaskId(request.id.0),
                to: meta.role.clone(),
                from: None,
                incident_id: request.incident_id,
                input,
                created_at: Utc::now(),
            };
            self.lock().queue.push_back(Queued {
                task: result,
                depth: meta.depth + 1,
                root: meta.root,
            });
        }
        for (reason, count) in rejected {
            self.count(|stats| stats.actions_rejected += count);
            tracing::warn!(
                role = actor,
                count,
                reason,
                "the runtime rejected proposed actions"
            );
            let entry = AuditEntry::new(
                AuditKind::Other,
                RUNTIME_ACTOR,
                format!(
                    "The runtime did not dispatch {count} actions of the {actor} agent from the \
                     task {}: {reason}.",
                    meta.id
                ),
            )
            .with_payload(json!({ "task_id": meta.id, "incident_id": meta.incident_id }))
            .with_evidence(meta.evidence.clone());
            self.audit(entry).await;
        }
    }

    /// Puts the new tasks of one task in the queue.
    async fn queue_tasks(&self, meta: &TaskMeta, tasks: Vec<AgentTask>) {
        let mut rejected: BTreeMap<Rejection, u64> = BTreeMap::new();
        for mut task in tasks {
            task.from = Some(meta.role.clone());
            if task.incident_id.is_none() {
                task.incident_id = meta.incident_id;
            }
            if let Err(rejection) = self.enqueue(task, meta.depth + 1, meta.root) {
                *rejected.entry(rejection).or_default() += 1;
            }
        }
        for (rejection, count) in rejected {
            if rejection == Rejection::NoAgent {
                // A role that the operator did not enable is not an error.
                tracing::debug!(
                    role = meta.role.token(),
                    count,
                    "dropped tasks for roles with no agent"
                );
                continue;
            }
            tracing::warn!(
                role = meta.role.token(),
                count,
                reason = rejection.reason(),
                "the runtime rejected tasks"
            );
            let entry = AuditEntry::new(
                AuditKind::Other,
                RUNTIME_ACTOR,
                format!(
                    "The runtime rejected {count} tasks of the {} agent from the task {}: {}.",
                    meta.role.token(),
                    meta.id,
                    rejection.reason()
                ),
            )
            .with_payload(json!({ "task_id": meta.id, "incident_id": meta.incident_id }))
            .with_evidence(meta.evidence.clone());
            self.audit(entry).await;
        }
    }

    /// Publishes a value on the bus. A bus failure does not stop the dispatch.
    async fn publish<T: Serialize + Sync>(&self, subject: &str, value: &T) {
        if let Err(error) = publish_json(self.context.bus.as_ref(), subject, value).await {
            let detail = one_line(&error.to_string());
            tracing::warn!(subject, error = %detail, "the bus did not take a message");
            let entry = AuditEntry::new(
                AuditKind::Other,
                RUNTIME_ACTOR,
                format!("The bus did not take a message on {subject}: {detail}"),
            );
            self.audit(entry).await;
        }
    }

    /// Counts and records a bus message that the runtime cannot use.
    async fn discard(&self, subject: &str, reason: &str) {
        self.count(|stats| stats.tasks_rejected += 1);
        self.record_discard(subject, reason).await;
    }

    /// Records a bus message that the runtime cannot use. The record has no payload.
    async fn record_discard(&self, subject: &str, reason: &str) {
        let subject = one_line(subject);
        let reason = one_line(reason);
        tracing::warn!(subject = %subject, reason = %reason, "discarded a bus message");
        let entry = AuditEntry::new(
            AuditKind::Other,
            RUNTIME_ACTOR,
            format!("The runtime discarded a message on {subject}: {reason}."),
        );
        self.audit(entry).await;
    }

    /// Takes one item of a bus subscription. An error means that [`Self::run`] must stop.
    async fn intake(
        &self,
        source: Intake,
        item: Option<Result<BusMessage>>,
        errors_in_sequence: &mut u32,
    ) -> Result<()> {
        match item {
            Some(Ok(message)) => {
                *errors_in_sequence = 0;
                match source {
                    Intake::Tasks => self.take_task_message(&message).await,
                    Intake::Incidents => self.take_incident_message(&message).await,
                }
                Ok(())
            }
            Some(Err(error)) => {
                *errors_in_sequence += 1;
                self.discard(source.subject(), &error.to_string()).await;
                if *errors_in_sequence >= MAX_BUS_ERRORS_IN_SEQUENCE {
                    return Err(Error::Unavailable(format!(
                        "the bus subscription for {} gave {MAX_BUS_ERRORS_IN_SEQUENCE} errors \
                         in sequence",
                        source.name()
                    )));
                }
                Ok(())
            }
            None => Err(Error::Unavailable(format!(
                "the bus subscription for {} ended",
                source.name()
            ))),
        }
    }

    async fn take_task_message(&self, message: &BusMessage) {
        let Ok(task) = message.decode::<AgentTask>() else {
            self.discard(&message.subject, "the payload is not a task")
                .await;
            return;
        };
        let expected = format!("{}.{}", subject::AGENT_TASKS, task.to.token());
        if message.subject != expected {
            self.discard(
                &message.subject,
                "the subject does not name the role of the task",
            )
            .await;
            return;
        }
        // The queue counted the rejection.
        if let Err(error) = self.submit(task) {
            self.record_discard(&message.subject, &error.to_string())
                .await;
        }
    }

    async fn take_incident_message(&self, message: &BusMessage) {
        let Ok(incident) = message.decode::<Incident>() else {
            self.discard(&message.subject, "the payload is not an incident")
                .await;
            return;
        };
        // The queue counted the rejection.
        if let Err(error) = self.submit_incident(incident) {
            self.record_discard(&message.subject, &error.to_string())
                .await;
        }
    }

    /// Queues one `Tick` task for each agent that has no `Tick` task in work.
    fn enqueue_ticks(&self) {
        let roles: Vec<AgentRole> = self.agents.keys().cloned().collect();
        for role in roles {
            if self.lock().pending_ticks.contains(&role) {
                continue;
            }
            let task = AgentTask::new(role.clone(), AgentInput::Tick);
            let root = task.id;
            match self.enqueue(task, 0, root) {
                Ok(()) => {
                    self.lock().pending_ticks.insert(role);
                }
                Err(rejection) => tracing::warn!(
                    role = role.token(),
                    reason = rejection.reason(),
                    "the runtime did not queue a tick"
                ),
            }
        }
    }
}

async fn next_tick(ticker: &mut Option<Interval>) {
    match ticker {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Records the end of a running task: frees its incident and its place in the step count.
fn release(inner: &mut Inner, task: RunningTask, state: TaskState, detail: Option<String>) {
    if let Some(id) = task.incident_id {
        inner.busy_incidents.remove(&id);
    }
    if task.is_root_tick {
        inner.pending_ticks.remove(&task.role);
    }
    if let Some(budget) = inner.roots.get_mut(&task.root) {
        budget.live = budget.live.saturating_sub(1);
        if budget.live == 0 {
            inner.roots.remove(&task.root);
        }
    }
    match state {
        TaskState::Completed => inner.stats.tasks_completed += 1,
        _ => inner.stats.tasks_failed += 1,
    }
    push_history(
        inner,
        TaskRecord {
            id: task.id,
            role: task.role,
            incident_id: task.incident_id,
            depth: task.depth,
            state,
            detail,
        },
    );
}

fn push_history(inner: &mut Inner, record: TaskRecord) {
    if inner.history.len() >= HISTORY_LIMIT {
        inner.history.pop_front();
    }
    inner.history.push_back(record);
}

fn input_kind(input: &AgentInput) -> &'static str {
    match input {
        AgentInput::Goal(_) => "goal",
        AgentInput::Tick => "tick",
        AgentInput::Event(_) => "event",
        AgentInput::Detection(_) => "detection",
        AgentInput::Incident(_) => "incident",
        AgentInput::ActionResult(_) => "action_result",
        AgentInput::Note(_) => "note",
    }
}

/// Returns the evidence links for the audit records of a task.
fn task_evidence(task: &AgentTask) -> Vec<EvidenceRef> {
    let mut links = Vec::new();
    if let Some(id) = task.incident_id {
        links.push(EvidenceRef::new(EvidenceKind::Incident, id));
    }
    match &task.input {
        AgentInput::Incident(incident) => {
            for link in support::evidence(incident) {
                if !links.contains(&link) {
                    links.push(link);
                }
            }
        }
        AgentInput::Detection(detection) => {
            links.push(EvidenceRef::new(EvidenceKind::Detection, detection.id));
            links.extend(
                detection
                    .event_ids
                    .iter()
                    .take(16)
                    .map(|id| EvidenceRef::new(EvidenceKind::Event, id)),
            );
        }
        AgentInput::Event(event) => links.push(EvidenceRef::new(EvidenceKind::Event, event.id)),
        AgentInput::ActionResult(disposition) => {
            if let aegis_contracts::ActionDisposition::Executed(outcome) = disposition.as_ref() {
                links.push(EvidenceRef::new(EvidenceKind::Action, outcome.action_id));
            }
        }
        AgentInput::Goal(_) | AgentInput::Tick | AgentInput::Note(_) => {}
    }
    links.truncate(MAX_EVIDENCE_PER_RECORD);
    links
}
