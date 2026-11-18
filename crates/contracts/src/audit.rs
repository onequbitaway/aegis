//! The hash-chained audit record and the audit log contract.
//!
//! # Hash chain
//!
//! Each [`AuditRecord`] holds the hash of the record before it. A change to a record, the
//! removal of a record, or a change of order breaks the chain. [`verify_chain`] finds the
//! first record that is not correct.
//!
//! The hash of a record is the SHA-256 digest, in lower-case hexadecimal, of the canonical
//! JSON form of the record without its `hash` field. The canonical JSON form has object keys
//! in byte order and no white space. Refer to [`canonical_json`].
//!
//! The first record has sequence number 1 and uses [`GENESIS_HASH`] as `prev_hash`.
//!
//! # Rules for stores
//!
//! A store must return each record with the same field values that it received. Record
//! times have microsecond precision, so a store must keep microseconds. A store must not
//! change the number format in `payload`.

use async_trait::async_trait;
use chrono::{DateTime, SubsecRound, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::{AuditId, EvidenceRef};
use crate::error::Result;

/// The `prev_hash` value of the first record in a chain.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The type of an audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// A detector made a detection.
    Detection,
    /// The correlator made or changed an incident.
    Incident,
    /// An agent made a decision.
    AgentDecision,
    /// An agent or a playbook proposed an action.
    ActionProposed,
    /// The policy engine evaluated an action.
    PolicyDecision,
    /// A gated action entered the approval queue.
    ApprovalRequested,
    /// A person approved or rejected a gated action.
    ApprovalDecided,
    /// A connector did an action, or simulated it in a dry run.
    ActionExecuted,
    /// An operator changed the configuration, the policy, or a rule pack.
    ConfigChange,
    /// A record that has no more specific variant.
    Other,
}

/// The data for a new audit record, before the log adds the chain fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The type of the record.
    pub kind: AuditKind,
    /// The component or the person that did the operation, for example `responder`.
    pub actor: String,
    /// One sentence that describes the operation.
    pub summary: String,
    /// The full data of the operation.
    #[serde(default)]
    pub payload: serde_json::Value,
    /// The evidence for the operation.
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

impl AuditEntry {
    /// Makes an entry with no payload and no evidence.
    pub fn new(kind: AuditKind, actor: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            kind,
            actor: actor.into(),
            summary: summary.into(),
            payload: serde_json::Value::Null,
            evidence: Vec::new(),
        }
    }

    /// Sets the payload.
    #[must_use]
    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }

    /// Sets the evidence.
    #[must_use]
    pub fn with_evidence(mut self, evidence: Vec<EvidenceRef>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// One record in the audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The position of the record in the chain. The first record has the value 1.
    pub sequence: u64,
    /// The identifier of the record.
    pub id: AuditId,
    /// The time at which the log sealed the record, with microsecond precision.
    pub time: DateTime<Utc>,
    /// The type of the record.
    pub kind: AuditKind,
    /// The component or the person that did the operation.
    pub actor: String,
    /// One sentence that describes the operation.
    pub summary: String,
    /// The full data of the operation.
    #[serde(default)]
    pub payload: serde_json::Value,
    /// The evidence for the operation.
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    /// The hash of the record before this one, or [`GENESIS_HASH`] for the first record.
    pub prev_hash: String,
    /// The hash of this record.
    pub hash: String,
}

impl AuditRecord {
    /// Computes the hash that this record must have.
    ///
    /// The result does not use the present value of the `hash` field.
    pub fn compute_hash(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        if let serde_json::Value::Object(fields) = &mut value {
            fields.remove("hash");
        }
        let digest = Sha256::digest(canonical_json(&value).as_bytes());
        Ok(hex::encode(digest))
    }
}

/// Returns the canonical JSON form of `value`.
///
/// Object keys are in byte order. The output has no white space. Two values that are equal
/// have the same canonical form.
#[must_use]
pub fn canonical_json(value: &serde_json::Value) -> String {
    let mut output = String::new();
    write_canonical(value, &mut output);
    output
}

fn write_canonical(value: &serde_json::Value, output: &mut String) {
    match value {
        serde_json::Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort_unstable();
            output.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::Value::String(key.clone()).to_string());
                output.push(':');
                if let Some(field) = fields.get(key) {
                    write_canonical(field, output);
                }
            }
            output.push('}');
        }
        serde_json::Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(item, output);
            }
            output.push(']');
        }
        scalar => output.push_str(&scalar.to_string()),
    }
}

/// Makes the next record in a chain.
///
/// `previous` is the last record in the chain, or `None` for the first record. `time` is
/// rounded down to microseconds.
pub fn seal(
    previous: Option<&AuditRecord>,
    entry: AuditEntry,
    time: DateTime<Utc>,
) -> Result<AuditRecord> {
    let (sequence, prev_hash) = match previous {
        Some(record) => (record.sequence + 1, record.hash.clone()),
        None => (1, GENESIS_HASH.to_owned()),
    };
    let mut record = AuditRecord {
        sequence,
        id: AuditId::new(),
        time: time.trunc_subsecs(6),
        kind: entry.kind,
        actor: entry.actor,
        summary: entry.summary,
        payload: entry.payload,
        evidence: entry.evidence,
        prev_hash,
        hash: String::new(),
    };
    record.hash = record.compute_hash()?;
    Ok(record)
}

/// The result of a chain check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerification {
    /// `true` if all checked records are correct.
    pub valid: bool,
    /// The number of records that the check examined before it stopped.
    pub checked: u64,
    /// The sequence number of the first record that is not correct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_invalid_sequence: Option<u64>,
    /// Why the first incorrect record is not correct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ChainVerification {
    fn invalid(checked: u64, sequence: u64, reason: String) -> Self {
        Self {
            valid: false,
            checked,
            first_invalid_sequence: Some(sequence),
            reason: Some(reason),
        }
    }
}

/// Checks a chain of records.
///
/// `anchor` is the record immediately before `records`, or `None` if `records` starts at the
/// first record of the log. The check stops at the first record that is not correct.
pub fn verify_chain(
    anchor: Option<&AuditRecord>,
    records: &[AuditRecord],
) -> Result<ChainVerification> {
    let (mut expected_sequence, mut expected_prev_hash) = match anchor {
        Some(record) => (record.sequence + 1, record.hash.as_str()),
        None => (1, GENESIS_HASH),
    };
    let mut checked = 0;
    for record in records {
        if record.sequence != expected_sequence {
            return Ok(ChainVerification::invalid(
                checked,
                record.sequence,
                format!(
                    "expected sequence {expected_sequence}, found {}",
                    record.sequence
                ),
            ));
        }
        if record.prev_hash != expected_prev_hash {
            return Ok(ChainVerification::invalid(
                checked,
                record.sequence,
                "prev_hash does not match the hash of the record before".to_owned(),
            ));
        }
        if record.hash != record.compute_hash()? {
            return Ok(ChainVerification::invalid(
                checked,
                record.sequence,
                "hash does not match the record contents".to_owned(),
            ));
        }
        checked += 1;
        expected_sequence = record.sequence + 1;
        expected_prev_hash = record.hash.as_str();
    }
    Ok(ChainVerification {
        valid: true,
        checked,
        first_invalid_sequence: None,
        reason: None,
    })
}

/// An append-only, hash-chained audit log.
///
/// An implementation must seal records with [`seal`]. It must never change or remove a
/// record.
#[async_trait]
pub trait AuditLog: Send + Sync {
    /// Seals `entry` as the next record and writes it.
    async fn append(&self, entry: AuditEntry) -> Result<AuditRecord>;

    /// Reads records in sequence order. The first record has `from_sequence` or the next
    /// larger sequence number.
    async fn read(&self, from_sequence: u64, limit: usize) -> Result<Vec<AuditRecord>>;

    /// Checks the full chain from the first record.
    async fn verify(&self) -> Result<ChainVerification>;
}
