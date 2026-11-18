//! The contract for agents and the task types.
//!
//! The agent runtime sends an [`AgentTask`] to an agent. The agent returns an
//! [`AgentOutput`]. The runtime then sends the new tasks to other agents and sends the
//! proposed actions to the [`ActionDispatcher`](crate::action::ActionDispatcher).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::action::{ActionDisposition, ActionRequest};
use crate::audit::AuditLog;
use crate::bus::MessageBus;
use crate::common::{IncidentId, TaskId};
use crate::detection::Detection;
use crate::error::Result;
use crate::event::Event;
use crate::graph::DefensiveGraph;
use crate::incident::{Incident, IncidentStore};
use crate::model::ModelProvider;

/// The function of an agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    /// Divides the goal of the operator into tasks.
    Supervisor,
    /// Monitors the live streams and keeps the situation picture current.
    Monitor,
    /// Hunts for threats and examines the external exposure of the assets of the operator.
    Hunter,
    /// Triages alerts, adds context, finds false positives, and builds the case.
    Analyst,
    /// Proposes containment actions.
    Responder,
    /// Plants honeytokens and honeypots, and monitors them.
    Deception,
    /// Writes incident reports and timelines.
    Reporter,
    /// A function that a plugin defines.
    Custom(String),
}

impl AgentRole {
    /// Returns the name of the role as one lower-case token, for use in a bus subject.
    #[must_use]
    pub fn token(&self) -> &str {
        match self {
            Self::Supervisor => "supervisor",
            Self::Monitor => "monitor",
            Self::Hunter => "hunter",
            Self::Analyst => "analyst",
            Self::Responder => "responder",
            Self::Deception => "deception",
            Self::Reporter => "reporter",
            Self::Custom(name) => name,
        }
    }
}

/// The data that a task gives to an agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInput {
    /// The goal of the operator, in natural language.
    Goal(String),
    /// A regular signal with no data. An agent uses it to do periodic work.
    Tick,
    /// One event to examine.
    Event(Box<Event>),
    /// One detection to triage.
    Detection(Box<Detection>),
    /// One incident to analyze, to contain, or to report.
    Incident(Box<Incident>),
    /// The result of an action that the agent proposed.
    ActionResult(Box<ActionDisposition>),
    /// A note from a different agent.
    Note(String),
}

/// One unit of work for one agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentTask {
    /// The identifier of the task.
    pub id: TaskId,
    /// The role that must do the task.
    pub to: AgentRole,
    /// The role that made the task. `None` means the operator or the runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AgentRole>,
    /// The incident that the task belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<IncidentId>,
    /// The data for the task.
    pub input: AgentInput,
    /// The time at which the task was made.
    pub created_at: DateTime<Utc>,
}

impl AgentTask {
    /// Makes a task with a new identifier and the present time.
    #[must_use]
    pub fn new(to: AgentRole, input: AgentInput) -> Self {
        Self {
            id: TaskId::new(),
            to,
            from: None,
            incident_id: None,
            input,
            created_at: Utc::now(),
        }
    }

    /// Sets the role that made the task.
    #[must_use]
    pub fn from_role(mut self, from: AgentRole) -> Self {
        self.from = Some(from);
        self
    }

    /// Sets the incident that the task belongs to.
    #[must_use]
    pub fn for_incident(mut self, incident_id: IncidentId) -> Self {
        self.incident_id = Some(incident_id);
        self
    }
}

/// What an agent returns for one task.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AgentOutput {
    /// New tasks for other agents.
    #[serde(default)]
    pub tasks: Vec<AgentTask>,
    /// Actions that the agent proposes. The runtime sends them to the dispatcher.
    #[serde(default)]
    pub actions: Vec<ActionRequest>,
    /// Incidents that the agent changed. The runtime writes them to the incident store.
    #[serde(default)]
    pub incidents: Vec<Incident>,
    /// Notes that explain the decisions of the agent. The runtime writes them to the audit log.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// The shared services that the runtime gives to each agent.
#[derive(Clone)]
pub struct AgentContext {
    /// The goal of the operator, in natural language.
    pub goal: String,
    /// Access to the models, usually through the model router.
    pub models: Arc<dyn ModelProvider>,
    /// The Defensive Graph.
    pub graph: Arc<dyn DefensiveGraph>,
    /// The incident store.
    pub incidents: Arc<dyn IncidentStore>,
    /// The audit log.
    pub audit: Arc<dyn AuditLog>,
    /// The message bus.
    pub bus: Arc<dyn MessageBus>,
}

/// An agent. It does one task at a time and returns new work for the runtime.
///
/// An implementation must be safe to share between tasks.
#[async_trait]
pub trait Agent: Send + Sync {
    /// Returns the role of this agent.
    fn role(&self) -> AgentRole;

    /// Does one task.
    async fn handle(&self, task: AgentTask, context: &AgentContext) -> Result<AgentOutput>;
}
