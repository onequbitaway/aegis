//! Test data and helpers that the integration tests share.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_agents::{AgentRuntime, RunReport, RuntimeConfig};
use aegis_contracts::action::ActionDispatcher;
use aegis_contracts::audit::{AuditKind, AuditRecord};
use aegis_contracts::common::{DetectionId, EntityKind, EntityRef, EventId, IncidentId, Severity};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
use aegis_contracts::event::{Event, Outcome, action, attr};
use aegis_contracts::graph::{GraphEdge, NodeId};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::{Agent, AgentContext, AgentOutput, AgentRole, AgentTask, Result};
use aegis_testkit::fixtures::{self, expected};
use aegis_testkit::{DispatchMode, Harness, RecordingDispatcher, ScriptedModel};
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::mpsc;

/// The standing goal of the operator in the tests.
pub const GOAL: &str = "Keep this tenant safe.";

/// The address of the password spray.
pub fn spray_ip() -> EntityRef {
    EntityRef::new(EntityKind::IpAddress, fixtures::SPRAY_IP.to_string())
}

/// The user whose password the spray found.
pub fn victim() -> EntityRef {
    EntityRef::new(EntityKind::User, fixtures::VICTIM_USER_ID)
        .with_name("dana@contoso.example")
        .with_tenant(fixtures::TENANT)
}

/// The rogue service principal.
pub fn rogue() -> EntityRef {
    EntityRef::new(EntityKind::ServicePrincipal, fixtures::ROGUE_PRINCIPAL_ID)
        .with_name("Sync Helper")
        .with_tenant(fixtures::TENANT)
}

/// The application of the attacker.
pub fn rogue_app() -> EntityRef {
    EntityRef::new(EntityKind::Application, fixtures::ROGUE_APP_ID)
        .with_name("Sync Helper")
        .with_tenant(fixtures::TENANT)
}

/// Returns the events of the recorded attack log that `select` accepts.
pub fn attack_events(select: impl Fn(&Event) -> bool) -> Vec<Event> {
    let events: Vec<Event> = fixtures::artex_style_attack()
        .into_iter()
        .filter(|event| select(event))
        .collect();
    assert!(!events.is_empty(), "the attack log must have these events");
    events
}

/// Makes the detection that a deterministic rule gives for `events`.
pub fn detection(
    rule_id: &str,
    technique: AttackTechnique,
    events: &[Event],
    entities: Vec<EntityRef>,
) -> Detection {
    let last = events.last().expect("a detection must have events");
    Detection {
        id: DetectionId::new(),
        rule_id: rule_id.to_owned(),
        title: format!("Rule {rule_id}"),
        description: format!("The rule {rule_id} found {} events.", events.len()),
        severity: Severity::High,
        verdict: Verdict::Malicious,
        tier: DetectionTier::Deterministic,
        time: last.time,
        attack: vec![technique],
        event_ids: events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<EventId>>(),
        entities,
        tenant: Some(fixtures::TENANT.to_owned()),
        attributes: BTreeMap::from([("event_count".to_owned(), json!(events.len()))]),
    }
}

/// Makes the incident that the recorded attack log gives: a critical incident with the
/// spray address, the victim user, and the rogue service principal.
pub fn attack_incident() -> Incident {
    let spray = attack_events(|event| {
        event.action == action::SIGN_IN
            && event.outcome == Outcome::Failure
            && event.actor.ip == Some(fixtures::SPRAY_IP)
    });
    assert_eq!(spray.len(), fixtures::SPRAY_ATTEMPTS);
    let consent = attack_events(|event| event.action == action::OAUTH_CONSENT_GRANT);
    let credential = attack_events(|event| event.action == action::APP_CREDENTIAL_ADD);
    let role = attack_events(|event| event.action == action::ROLE_ASSIGN);
    let api = attack_events(|event| {
        event.action == action::API_CALL && event.actor.id == fixtures::ROGUE_PRINCIPAL_ID
    });

    let mut credential_add = detection(
        "velocity.credential_after_grant",
        AttackTechnique::new(
            "persistence",
            expected::CREDENTIAL_ADD,
            "Additional Cloud Credentials",
        ),
        &credential,
        vec![rogue(), victim()],
    );
    let credential_id = credential[0]
        .attribute_str(attr::CREDENTIAL_ID)
        .expect("the event must name the credential");
    credential_add
        .attributes
        .insert(attr::CREDENTIAL_ID.to_owned(), json!(credential_id));

    let detections = vec![
        detection(
            "velocity.sign_in_burst",
            AttackTechnique::new(
                "credential-access",
                expected::PASSWORD_SPRAY,
                "Password Spraying",
            ),
            &spray,
            vec![spray_ip(), victim()],
        ),
        detection(
            "sigma.consent_to_privileged_scopes",
            AttackTechnique::new(
                "credential-access",
                expected::CONSENT_GRANT,
                "Steal Application Access Token",
            ),
            &consent,
            vec![victim(), rogue_app()],
        ),
        credential_add,
        detection(
            "velocity.self_role_assignment",
            AttackTechnique::new(
                "privilege-escalation",
                expected::ROLE_ASSIGN,
                "Additional Cloud Roles",
            ),
            &role,
            vec![rogue()],
        ),
        detection(
            "velocity.cross_tenant_api_calls",
            AttackTechnique::new("initial-access", expected::CLOUD_ACCOUNT, "Cloud Accounts"),
            &api,
            vec![rogue()],
        ),
    ];
    let last = detections
        .iter()
        .map(|detection| detection.time)
        .max()
        .expect("the incident must have detections");
    Incident {
        id: IncidentId::new(),
        title: "Password spray and rogue service principal".to_owned(),
        summary: String::new(),
        severity: Severity::Critical,
        status: IncidentStatus::Open,
        created_at: last,
        updated_at: last,
        tenant: Some(fixtures::TENANT.to_owned()),
        attack: detections
            .iter()
            .flat_map(|detection| detection.attack.clone())
            .collect(),
        entities: vec![spray_ip(), victim(), rogue()],
        detections,
        timeline: Vec::new(),
    }
}

/// Makes an incident with one detection that is only suspicious.
pub fn suspicious_incident() -> Incident {
    let sign_in = attack_events(|event| {
        event.action == action::SIGN_IN
            && event.outcome == Outcome::Success
            && event.actor.id == fixtures::VICTIM_USER_ID
    });
    let mut anomaly = detection(
        "anomaly.sign_in_from_new_country",
        AttackTechnique::new("initial-access", "T1078", "Valid Accounts"),
        &sign_in,
        vec![victim()],
    );
    anomaly.verdict = Verdict::Suspicious;
    anomaly.severity = Severity::Medium;
    Incident {
        id: IncidentId::new(),
        title: "Sign-in from a new country".to_owned(),
        summary: String::new(),
        severity: Severity::Medium,
        status: IncidentStatus::Open,
        created_at: anomaly.time,
        updated_at: anomaly.time,
        tenant: Some(fixtures::TENANT.to_owned()),
        attack: anomaly.attack.clone(),
        entities: vec![victim()],
        detections: vec![anomaly],
        timeline: Vec::new(),
    }
}

/// One runtime with the in-memory services of the test kit.
pub struct Bench {
    /// The in-memory services.
    pub harness: Harness,
    /// The dispatcher that records each request.
    pub dispatcher: Arc<RecordingDispatcher>,
    /// The runtime under test.
    pub runtime: Arc<AgentRuntime>,
}

impl Bench {
    /// Makes a runtime with the built-in agents.
    pub fn with_default_agents(
        model: ScriptedModel,
        mode: DispatchMode,
        config: RuntimeConfig,
    ) -> Self {
        Self::build(model, mode, config, true, Vec::new())
    }

    /// Makes a runtime with only the agents of `agents`.
    pub fn with_agents(config: RuntimeConfig, agents: Vec<Arc<dyn Agent>>) -> Self {
        Self::build(
            ScriptedModel::new("scripted"),
            DispatchMode::Execute,
            config,
            false,
            agents,
        )
    }

    fn build(
        model: ScriptedModel,
        mode: DispatchMode,
        config: RuntimeConfig,
        built_in: bool,
        agents: Vec<Arc<dyn Agent>>,
    ) -> Self {
        let harness = Harness::new(model);
        let dispatcher = Arc::new(RecordingDispatcher::new(mode));
        let mut builder =
            AgentRuntime::builder(harness.context(GOAL), dispatcher.clone()).config(config);
        if built_in {
            builder = builder.with_default_agents();
        }
        for agent in agents {
            builder = builder.agent(agent);
        }
        let runtime = Arc::new(builder.build().expect("the runtime must build"));
        Self {
            harness,
            dispatcher,
            runtime,
        }
    }

    /// Runs the queue until it is empty. A runtime that does not become idle fails the test.
    pub async fn drive(&self) -> RunReport {
        drive(&self.runtime).await
    }

    /// Reads an incident that the store must have.
    pub async fn stored(&self, id: IncidentId) -> Incident {
        self.harness
            .incidents
            .get(id)
            .await
            .expect("the store must answer")
            .expect("the store must have the incident")
    }

    /// Returns the audit records of one type.
    pub fn audit_of(&self, kind: AuditKind) -> Vec<AuditRecord> {
        self.harness
            .audit
            .records()
            .into_iter()
            .filter(|record| record.kind == kind)
            .collect()
    }

    /// Returns `true` if the graph has the relation.
    pub fn has_edge(&self, from: &NodeId, relation: &str, to: &NodeId) -> bool {
        has_edge(&self.harness.graph.edges(), from, relation, to)
    }
}

/// Makes a runtime with only the agents of `agents`, for a test that replaces a service.
pub fn runtime_with(
    context: AgentContext,
    dispatcher: Arc<dyn ActionDispatcher>,
    config: RuntimeConfig,
    agents: Vec<Arc<dyn Agent>>,
) -> Arc<AgentRuntime> {
    let mut builder = AgentRuntime::builder(context, dispatcher).config(config);
    for agent in agents {
        builder = builder.agent(agent);
    }
    Arc::new(builder.build().expect("the runtime must build"))
}

/// Runs the queue of `runtime` until it is empty.
pub async fn drive(runtime: &AgentRuntime) -> RunReport {
    tokio::time::timeout(Duration::from_secs(30), runtime.run_until_idle())
        .await
        .expect("the runtime must become idle")
        .expect("the runtime must run")
}

/// Returns `true` if `edges` has the relation.
pub fn has_edge(edges: &[GraphEdge], from: &NodeId, relation: &str, to: &NodeId) -> bool {
    edges
        .iter()
        .any(|edge| &edge.from == from && edge.relation == relation && &edge.to == to)
}

/// A configuration with only `roles` enabled and with the default limits.
pub fn config_for(roles: &[AgentRole]) -> RuntimeConfig {
    RuntimeConfig {
        enabled_roles: roles.to_vec(),
        ..RuntimeConfig::default()
    }
}

/// The function that a [`Probe`] runs for each task.
pub type Respond = Box<dyn Fn(&AgentTask) -> Result<AgentOutput> + Send + Sync>;

/// An agent that records each task and answers with a function.
pub struct Probe {
    role: AgentRole,
    seen: Mutex<Vec<AgentTask>>,
    respond: Respond,
}

impl Probe {
    /// Makes an agent for `role` that answers each task with `respond`.
    pub fn new(
        role: AgentRole,
        respond: impl Fn(&AgentTask) -> Result<AgentOutput> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            role,
            seen: Mutex::default(),
            respond: Box::new(respond),
        })
    }

    /// Makes an agent for `role` that returns an empty output.
    pub fn quiet(role: AgentRole) -> Arc<Self> {
        Self::new(role, |_| Ok(AgentOutput::default()))
    }

    /// Returns the tasks that the agent received, oldest first.
    pub fn seen(&self) -> Vec<AgentTask> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl Agent for Probe {
    fn role(&self) -> AgentRole {
        self.role.clone()
    }

    async fn handle(&self, task: AgentTask, _: &AgentContext) -> Result<AgentOutput> {
        self.seen.lock().unwrap().push(task.clone());
        (self.respond)(&task)
    }
}

/// An agent that sends each task to a channel and returns an empty output.
pub struct Tap {
    role: AgentRole,
    tasks: mpsc::UnboundedSender<AgentTask>,
}

/// Makes a [`Tap`] for `role` and the channel that gets its tasks.
pub fn tap(role: AgentRole) -> (Arc<Tap>, mpsc::UnboundedReceiver<AgentTask>) {
    let (tasks, receiver) = mpsc::unbounded_channel();
    (Arc::new(Tap { role, tasks }), receiver)
}

#[async_trait]
impl Agent for Tap {
    fn role(&self) -> AgentRole {
        self.role.clone()
    }

    async fn handle(&self, task: AgentTask, _: &AgentContext) -> Result<AgentOutput> {
        // The test can drop the channel before the runtime stops.
        let _ = self.tasks.send(task);
        Ok(AgentOutput::default())
    }
}

/// Waits for the next task of a [`Tap`]. A task that does not arrive in `limit` fails the
/// test.
pub async fn next_task(
    tasks: &mut mpsc::UnboundedReceiver<AgentTask>,
    limit: Duration,
) -> AgentTask {
    tokio::time::timeout(limit, tasks.recv())
        .await
        .expect("the agent must get a task")
        .expect("the agent must be alive")
}
