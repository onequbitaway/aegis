//! Runs the API and the web console with sample data in memory.
//!
//! Use this example to look at the console with no other AEGIS service. All data is in
//! memory. The agents run in dry-run mode on one sample incident, so the console has an
//! incident, graph nodes, approval requests, and audit records to show.
//!
//! ```sh
//! AEGIS_DEMO_TOKEN="$(openssl rand -hex 32)" cargo run -p aegis-api --example console_demo
//! ```
//!
//! Then open `http://127.0.0.1:8080/` and enter the token. Set `AEGIS_DEMO_BIND` to use a
//! different loopback address.
//!
//! The approval path of this example only records the decision in the in-memory queue. It
//! runs no action. The composition root of AEGIS has the real approval path.

use std::collections::BTreeMap;
use std::sync::Arc;

use aegis_agents::AgentRuntime;
use aegis_api::{
    ApiConfig, ApiParts, ApiState, ApprovalActions, ApprovalDecision, PrincipalConfig,
};
use aegis_contracts::action::ActionKind;
use aegis_contracts::agent::AgentContext;
use aegis_contracts::common::{
    ApprovalId, DetectionId, EntityKind, EntityRef, IncidentId, Severity,
};
use aegis_contracts::detection::{AttackTechnique, Detection, DetectionTier, Verdict};
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore, TimelineEntry};
use aegis_contracts::policy::{ApprovalQueue, Principal};
use aegis_core::{ModuleSet, Shutdown};
use aegis_policy::{Permission, Rbac, RbacConfig};
use aegis_respond::{ActionRegistry, Dispatcher, PlaybookEngine};
use aegis_testkit::{
    MemoryApprovals, MemoryAuditLog, MemoryBus, MemoryGraph, MemoryIncidents, RecordingConnector,
    ScriptedModel, StaticPolicy,
};
use async_trait::async_trait;
use chrono::Utc;

const TOKEN_VARIABLE: &str = "AEGIS_DEMO_TOKEN";
const BIND_VARIABLE: &str = "AEGIS_DEMO_BIND";

/// An approval path that records the decision in the queue and runs no action.
struct RecordOnly {
    queue: Arc<MemoryApprovals>,
}

#[async_trait]
impl ApprovalActions for RecordOnly {
    async fn decide(
        &self,
        id: ApprovalId,
        approve: bool,
        principal: &Principal,
        note: Option<String>,
    ) -> aegis_contracts::Result<ApprovalDecision> {
        let request = self.queue.decide(id, approve, principal, note).await?;
        Ok(ApprovalDecision {
            request,
            disposition: None,
        })
    }
}

/// Makes the sample incident: a password spray and a rogue service principal.
fn sample_incident() -> Incident {
    let time = Utc::now();
    let techniques = vec![
        AttackTechnique::new("credential-access", "T1110.003", "Password Spraying"),
        AttackTechnique::new("persistence", "T1098.001", "Additional Cloud Credentials"),
    ];
    let entities = vec![
        EntityRef::new(EntityKind::IpAddress, "203.0.113.50"),
        EntityRef::new(EntityKind::User, "user-dana").with_name("dana@contoso.example"),
        EntityRef::new(EntityKind::ServicePrincipal, "sp-sync-helper").with_name("sync-helper"),
    ];
    Incident {
        id: IncidentId::new(),
        title: "Password spray and a new credential on a service principal".to_owned(),
        summary: "One address failed to sign in to many accounts. Then one account added a \
                  credential to a service principal."
            .to_owned(),
        severity: Severity::High,
        status: IncidentStatus::Open,
        created_at: time,
        updated_at: time,
        tenant: Some("tenant-contoso".to_owned()),
        detections: vec![Detection {
            id: DetectionId::new(),
            rule_id: "aegis.velocity.sign_in_burst".to_owned(),
            title: "Password spray".to_owned(),
            description: "600 failed sign-ins from one address in 30 seconds.".to_owned(),
            severity: Severity::High,
            verdict: Verdict::Malicious,
            tier: DetectionTier::Deterministic,
            time,
            attack: techniques.clone(),
            event_ids: Vec::new(),
            entities: entities.clone(),
            tenant: Some("tenant-contoso".to_owned()),
            attributes: BTreeMap::new(),
        }],
        entities,
        attack: techniques,
        timeline: vec![TimelineEntry {
            time,
            author: "correlator".to_owned(),
            description: "The correlator made the incident from one detection.".to_owned(),
            evidence: Vec::new(),
        }],
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let incidents = Arc::new(MemoryIncidents::default());
    let graph = Arc::new(MemoryGraph::default());
    let audit = Arc::new(MemoryAuditLog::default());
    let approvals = Arc::new(MemoryApprovals::default());
    let bus = Arc::new(MemoryBus::default());

    // The connector records each request and changes nothing.
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(RecordingConnector::new(
        "demo",
        vec![
            ActionKind::Tag,
            ActionKind::Notify,
            ActionKind::BlockIp,
            ActionKind::KillSession,
            ActionKind::DisableUser,
            ActionKind::DisableServicePrincipal,
            ActionKind::RevokeCredential,
        ],
    )))?;
    let dispatcher = Arc::new(
        Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::ByTier),
            approvals.clone(),
            audit.clone(),
        )
        .incidents(incidents.clone())
        .bus(bus.clone())
        .dry_run(true)
        .build(),
    );

    let context = AgentContext {
        goal: "Keep this tenant safe.".to_owned(),
        models: Arc::new(ScriptedModel::new("none")),
        graph: graph.clone(),
        incidents: incidents.clone(),
        audit: audit.clone(),
        bus: bus.clone(),
    };
    let agents = Arc::new(
        AgentRuntime::builder(context, dispatcher.clone())
            .with_default_agents()
            .build()?,
    );

    let incident = sample_incident();
    incidents.save(&incident).await?;
    agents.submit_incident(incident)?;
    agents.run_until_idle().await?;

    let rbac = Rbac::new(RbacConfig::default().with_role("demo", &Permission::ALL));
    let state = ApiState::new(ApiParts {
        incidents,
        graph,
        audit,
        approvals: approvals.clone(),
        bus,
        rbac,
        agents,
        playbooks: Arc::new(PlaybookEngine::new(dispatcher)),
        approval_actions: Arc::new(RecordOnly { queue: approvals }),
        modules: ModuleSet::all(),
    });

    let mut config = ApiConfig {
        principals: vec![PrincipalConfig::human(
            "demo@example.com",
            &["demo"],
            TOKEN_VARIABLE,
        )],
        ..ApiConfig::default()
    };
    if let Ok(bind) = std::env::var(BIND_VARIABLE) {
        config.bind = bind.parse()?;
    }

    let shutdown = Shutdown::new();
    shutdown.listen_for_signals()?;
    println!("The console is at http://{}/", config.bind);
    aegis_api::serve(state, config, shutdown).await?;
    Ok(())
}
