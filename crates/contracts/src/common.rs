//! Identifiers and small types that many contracts share.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Error;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Makes a new identifier. The identifier is a version 7 UUID, which sorts by time.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl std::str::FromStr for $name {
            type Err = Error;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(text).map(Self).map_err(|error| {
                    Error::InvalidInput(format!(
                        "{} is not a valid {}: {error}",
                        text,
                        stringify!($name)
                    ))
                })
            }
        }
    };
}

id_type!(
    /// The identifier of an [`Event`](crate::event::Event).
    EventId
);
id_type!(
    /// The identifier of a [`Detection`](crate::detection::Detection).
    DetectionId
);
id_type!(
    /// The identifier of an [`Incident`](crate::incident::Incident).
    IncidentId
);
id_type!(
    /// The identifier of an [`ActionRequest`](crate::action::ActionRequest).
    ActionId
);
id_type!(
    /// The identifier of an [`ApprovalRequest`](crate::policy::ApprovalRequest).
    ApprovalId
);
id_type!(
    /// The identifier of an [`AuditRecord`](crate::audit::AuditRecord).
    AuditId
);
id_type!(
    /// The identifier of an [`AgentTask`](crate::agent::AgentTask).
    TaskId
);

/// How important an event, a detection, or an incident is.
///
/// The variants are in order. `Critical` is the largest value.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// No security effect.
    #[default]
    Informational,
    /// A small security effect.
    Low,
    /// A moderate security effect.
    Medium,
    /// A large security effect.
    High,
    /// The largest security effect. Immediate action is necessary.
    Critical,
}

/// The type of an entity in the environment of the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// A human user account.
    User,
    /// A service principal or a workload identity.
    ServicePrincipal,
    /// An application registration.
    Application,
    /// A managed device.
    Device,
    /// A server or a workstation.
    Host,
    /// An IP address.
    IpAddress,
    /// A DNS domain.
    Domain,
    /// A tenant or an organization.
    Tenant,
    /// A sign-in session.
    Session,
    /// A secret, a key, or a credential.
    Secret,
    /// A directory role or a permission.
    Role,
    /// A cloud resource that has no more specific variant.
    Resource,
    /// An entity that has no more specific variant.
    Other,
}

/// A reference to one entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityRef {
    /// The type of the entity.
    pub kind: EntityKind,
    /// The identifier that the source system gives to the entity.
    pub id: String,
    /// The display name of the entity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The tenant that owns the entity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

impl EntityRef {
    /// Makes a reference with no name and no tenant.
    pub fn new(kind: EntityKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
            name: None,
            tenant: None,
        }
    }

    /// Sets the display name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }
}

/// The type of an item of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// An [`Event`](crate::event::Event).
    Event,
    /// A [`Detection`](crate::detection::Detection).
    Detection,
    /// An [`Incident`](crate::incident::Incident).
    Incident,
    /// An [`ActionRequest`](crate::action::ActionRequest).
    Action,
    /// An [`AuditRecord`](crate::audit::AuditRecord).
    AuditRecord,
    /// An item in an external system, for example a ticket.
    External,
}

/// A link from a decision or an action to the evidence for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// The type of the evidence.
    pub kind: EvidenceKind,
    /// The identifier of the evidence.
    pub id: String,
    /// A short explanation of why this evidence is relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl EvidenceRef {
    /// Makes a link with no note.
    pub fn new(kind: EvidenceKind, id: impl ToString) -> Self {
        Self {
            kind,
            id: id.to_string(),
            note: None,
        }
    }

    /// Sets the note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// A time range. `start` is inclusive and `end` is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    /// The first instant in the range.
    pub start: DateTime<Utc>,
    /// The first instant after the range.
    pub end: DateTime<Utc>,
}

impl TimeRange {
    /// Returns `true` if `instant` is in the range.
    #[must_use]
    pub fn contains(&self, instant: DateTime<Utc>) -> bool {
        self.start <= instant && instant < self.end
    }
}
