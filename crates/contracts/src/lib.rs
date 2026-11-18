//! Shared contracts for AEGIS.
//!
//! All other AEGIS crates compile against the traits and types in this crate. A crate talks
//! to a different subsystem only through these contracts.
//!
//! # Stability
//!
//! The contracts are frozen. Do not change this crate as a part of other work. Open an
//! issue first, because a change here affects all crates.
//!
//! # Modules
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`event`] | The normalized event that all source connectors emit. |
//! | [`source`] | The [`SourceConnector`] contract for telemetry inputs. |
//! | [`detection`] | The [`Detector`] contract and the [`Detection`] type. |
//! | [`incident`] | The [`Incident`] type and its store. |
//! | [`model`] | The [`ModelProvider`] contract for LLM access. |
//! | [`agent`] | The [`Agent`] contract and the task types. |
//! | [`action`] | The [`ActionConnector`] contract for response actions. |
//! | [`policy`] | The [`PolicyEngine`] contract, decisions, and approvals. |
//! | [`audit`] | The hash-chained [`AuditRecord`] and the [`AuditLog`] contract. |
//! | [`graph`] | The Defensive Graph and the vector store. |
//! | [`bus`] | The message bus between subsystems. |

pub mod action;
pub mod agent;
pub mod audit;
pub mod bus;
pub mod common;
pub mod detection;
pub mod error;
pub mod event;
pub mod graph;
pub mod incident;
pub mod model;
pub mod policy;
pub mod source;

pub use action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest,
    ActionResult, ActionStatus,
};
pub use agent::{Agent, AgentContext, AgentInput, AgentOutput, AgentRole, AgentTask};
pub use audit::{AuditEntry, AuditKind, AuditLog, AuditRecord, ChainVerification};
pub use bus::{BusMessage, MessageBus};
pub use common::{
    ActionId, ApprovalId, AuditId, DetectionId, EntityKind, EntityRef, EventId, EvidenceKind,
    EvidenceRef, IncidentId, Severity, TaskId, TimeRange,
};
pub use detection::{AttackTechnique, Detection, DetectionTier, Detector, Verdict};
pub use error::{Error, Result};
pub use event::{Actor, Event, EventClass, EventSource, Outcome};
pub use graph::{DefensiveGraph, GraphEdge, GraphNode, NodeId, NodeKind, VectorStore};
pub use incident::{Incident, IncidentStatus, IncidentStore, TimelineEntry};
pub use model::{
    ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse, Message, ModelProvider, Role,
    TaskKind, ToolCall, ToolSpec,
};
pub use policy::{
    ActionTier, ApprovalQueue, ApprovalRequest, ApprovalStatus, PolicyDecision, PolicyEffect,
    PolicyEngine, PolicyInput, Principal, PrincipalKind,
};
pub use source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
