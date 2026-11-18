//! The incident store.
//!
//! The `document` column holds the full incident as JSON text. It is the source of truth.
//! The other columns are copies for filters and for the sort order.
//!
//! The sort order uses the full creation time. The `created_at` column keeps microseconds,
//! and the `created_at_nanos` column keeps the nanoseconds that remain.

use aegis_contracts::Result;
use aegis_contracts::common::IncidentId;
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use async_trait::async_trait;
use sqlx::postgres::PgPool;

use crate::error::{db_error, decode_error};
use crate::json::{split_time, sql_limit, variant_name};

const SAVE: &str = "INSERT INTO aegis.incidents \
         (id, status, severity, tenant, created_at, created_at_nanos, updated_at, document) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     ON CONFLICT (id) DO UPDATE SET \
         status = EXCLUDED.status, \
         severity = EXCLUDED.severity, \
         tenant = EXCLUDED.tenant, \
         created_at = EXCLUDED.created_at, \
         created_at_nanos = EXCLUDED.created_at_nanos, \
         updated_at = EXCLUDED.updated_at, \
         document = EXCLUDED.document";

const GET: &str = "SELECT document FROM aegis.incidents WHERE id = $1";

const LIST: &str = "SELECT document FROM aegis.incidents \
     ORDER BY created_at DESC, created_at_nanos DESC, id ASC \
     LIMIT $1";

const LIST_WITH_STATUS: &str = "SELECT document FROM aegis.incidents \
     WHERE status = $1 \
     ORDER BY created_at DESC, created_at_nanos DESC, id ASC \
     LIMIT $2";

/// Reads an incident from its JSON document.
fn incident_from_document(document: &str) -> Result<Incident> {
    serde_json::from_str(document).map_err(|error| decode_error("an incident", error))
}

/// The incident store in the table `aegis.incidents`.
///
/// Get a value from [`PgStore::incidents`](crate::PgStore::incidents).
#[derive(Debug, Clone)]
pub struct PgIncidents {
    pool: PgPool,
}

impl PgIncidents {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IncidentStore for PgIncidents {
    async fn save(&self, incident: &Incident) -> Result<()> {
        let document = serde_json::to_string(incident)?;
        let (created_at, created_at_nanos) = split_time(incident.created_at);
        sqlx::query(SAVE)
            .bind(incident.id.0)
            .bind(variant_name(&incident.status)?)
            .bind(variant_name(&incident.severity)?)
            .bind(incident.tenant.as_deref())
            .bind(created_at)
            .bind(created_at_nanos)
            .bind(incident.updated_at)
            .bind(document)
            .execute(&self.pool)
            .await
            .map_err(|error| db_error("write the incident", error))?;
        Ok(())
    }

    async fn get(&self, id: IncidentId) -> Result<Option<Incident>> {
        let document: Option<String> = sqlx::query_scalar(GET)
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db_error("read the incident", error))?;
        document.as_deref().map(incident_from_document).transpose()
    }

    /// Lists incidents by creation time, newest first.
    ///
    /// Incidents with the same creation time are in the order of their identifiers.
    async fn list(&self, status: Option<IncidentStatus>, limit: usize) -> Result<Vec<Incident>> {
        const OPERATION: &str = "list the incidents";
        let documents: Vec<String> = match status {
            Some(status) => {
                sqlx::query_scalar(LIST_WITH_STATUS)
                    .bind(variant_name(&status)?)
                    .bind(sql_limit(limit))
                    .fetch_all(&self.pool)
                    .await
            }
            None => {
                sqlx::query_scalar(LIST)
                    .bind(sql_limit(limit))
                    .fetch_all(&self.pool)
                    .await
            }
        }
        .map_err(|error| db_error(OPERATION, error))?;
        documents
            .iter()
            .map(|document| incident_from_document(document))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::Error;
    use aegis_contracts::common::Severity;
    use chrono::{TimeZone, Utc};

    use super::*;

    #[test]
    fn a_document_gives_back_the_same_incident() {
        let incident = Incident {
            id: IncidentId::new(),
            title: "Credential added to an application".to_owned(),
            summary: "A service principal got a new secret.".to_owned(),
            severity: Severity::High,
            status: IncidentStatus::Investigating,
            created_at: Utc.with_ymd_and_hms(2026, 5, 6, 7, 8, 9).unwrap()
                + chrono::Duration::nanoseconds(123_456_789),
            updated_at: Utc.with_ymd_and_hms(2026, 5, 6, 7, 9, 0).unwrap(),
            tenant: Some("contoso".to_owned()),
            detections: Vec::new(),
            entities: Vec::new(),
            attack: Vec::new(),
            timeline: Vec::new(),
        };
        let document = serde_json::to_string(&incident).unwrap();
        assert_eq!(incident_from_document(&document).unwrap(), incident);
    }

    #[test]
    fn a_document_that_is_not_an_incident_is_a_serialization_error() {
        let error = incident_from_document(r#"{"id": "not-a-uuid"}"#).unwrap_err();
        match error {
            Error::Serialization(message) => {
                assert!(message.starts_with("storage: an incident cannot be decoded"));
            }
            other => panic!("expected Serialization, got {other:?}"),
        }
    }
}
