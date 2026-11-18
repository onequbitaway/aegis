//! The vector store on pgvector.
//!
//! The table `aegis.vectors` holds one row for each record. The table
//! `aegis.vector_collections` holds the number of dimensions of each collection. The first
//! record of a collection sets that number.
//!
//! A write runs in one transaction. Thus a write that fails does not leave an empty
//! collection with a fixed number of dimensions.
//!
//! A search reads all records of the collection and sorts them by cosine similarity. This
//! exact search has no index for the vector order.

use aegis_contracts::graph::{VectorMatch, VectorRecord, VectorStore};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use sqlx::postgres::PgPool;

use crate::error::{db_error, decode_error};
use crate::json::sql_limit;

/// The largest number of dimensions of an embedding. This is the limit of pgvector.
pub const MAX_DIMENSIONS: usize = 16_000;

const ENSURE_COLLECTION: &str = "INSERT INTO aegis.vector_collections (name, dimensions) \
     VALUES ($1, $2) \
     ON CONFLICT (name) DO NOTHING";

const READ_DIMENSIONS: &str = "SELECT dimensions FROM aegis.vector_collections WHERE name = $1";

/// Writes a record only if the collection has the same number of dimensions.
const UPSERT_RECORD: &str = "INSERT INTO aegis.vectors \
         (collection, id, dimensions, embedding, content, metadata, updated_at) \
     SELECT c.name, $2, c.dimensions, $3::real[]::vector, $4, $5, now() \
     FROM aegis.vector_collections AS c \
     WHERE c.name = $1 AND c.dimensions = $6 \
     ON CONFLICT (collection, id) DO UPDATE SET \
         embedding = EXCLUDED.embedding, \
         content = EXCLUDED.content, \
         metadata = EXCLUDED.metadata, \
         updated_at = EXCLUDED.updated_at";

/// Lists the records of a collection, nearest first.
///
/// `<=>` is the cosine distance of pgvector. The similarity is 1 minus the distance. The
/// distance to a vector of zero length is not a number, and its similarity is 0 here.
/// Records with the same similarity are in the byte order of their identifiers.
const SEARCH: &str = "SELECT v.id, v.embedding::real[], v.content, v.metadata, \
         COALESCE(NULLIF(1 - (v.embedding <=> $2::real[]::vector), 'NaN'::double precision), 0)::real \
             AS score \
     FROM aegis.vectors AS v \
     WHERE v.collection = $1 \
     ORDER BY score DESC, v.id COLLATE \"C\" ASC \
     LIMIT $3";

/// Checks an embedding before it goes to the database.
fn check_embedding(what: &str, embedding: &[f32]) -> Result<i32> {
    if embedding.is_empty() {
        return Err(Error::InvalidInput(format!(
            "vectors: {what} has an empty embedding"
        )));
    }
    if embedding.len() > MAX_DIMENSIONS {
        return Err(Error::InvalidInput(format!(
            "vectors: {what} has {} dimensions, and the limit is {MAX_DIMENSIONS}",
            embedding.len()
        )));
    }
    if let Some(index) = embedding.iter().position(|value| !value.is_finite()) {
        return Err(Error::InvalidInput(format!(
            "vectors: {what} has a value at index {index} that is not a finite number"
        )));
    }
    i32::try_from(embedding.len())
        .map_err(|_| Error::InvalidInput(format!("vectors: {what} has too many dimensions")))
}

fn dimension_mismatch(what: &str, found: usize, collection: &str, expected: i32) -> Error {
    Error::InvalidInput(format!(
        "vectors: {what} has {found} dimensions, but collection {collection} has {expected}"
    ))
}

/// Makes a search result from one row.
fn match_from_row(
    id: String,
    embedding: Vec<f32>,
    content: String,
    metadata: &str,
    score: f32,
) -> Result<VectorMatch> {
    let metadata = serde_json::from_str(metadata)
        .map_err(|error| decode_error("the metadata of a vector record", error))?;
    Ok(VectorMatch {
        record: VectorRecord {
            id,
            embedding,
            text: content,
            metadata,
        },
        score,
    })
}

/// The vector store in the table `aegis.vectors`.
///
/// Get a value from [`PgStore::vectors`](crate::PgStore::vectors).
#[derive(Debug, Clone)]
pub struct PgVectors {
    pool: PgPool,
}

impl PgVectors {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn dimensions(&self, operation: &str, collection: &str) -> Result<Option<i32>> {
        sqlx::query_scalar(READ_DIMENSIONS)
            .bind(collection)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db_error(operation, error))
    }
}

#[async_trait]
impl VectorStore for PgVectors {
    /// Writes a record. The first record of a collection sets its number of dimensions.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`]: the embedding is empty, has a value that is not finite, or
    /// has a different number of dimensions than the collection.
    async fn upsert(&self, collection: &str, record: VectorRecord) -> Result<()> {
        const OPERATION: &str = "write the vector record";
        let what = format!("vector record {}", record.id);
        let dimensions = check_embedding(&what, &record.embedding)?;
        let metadata = serde_json::to_string(&record.metadata)?;

        let failed = |error| db_error(OPERATION, error);
        let mut transaction = self.pool.begin().await.map_err(failed)?;
        sqlx::query(ENSURE_COLLECTION)
            .bind(collection)
            .bind(dimensions)
            .execute(&mut *transaction)
            .await
            .map_err(failed)?;
        let written = sqlx::query(UPSERT_RECORD)
            .bind(collection)
            .bind(&record.id)
            .bind(&record.embedding)
            .bind(&record.text)
            .bind(&metadata)
            .bind(dimensions)
            .execute(&mut *transaction)
            .await
            .map_err(failed)?;
        if written.rows_affected() == 1 {
            return transaction.commit().await.map_err(failed);
        }
        // No row: the collection has a different number of dimensions.
        let expected: Option<i32> = sqlx::query_scalar(READ_DIMENSIONS)
            .bind(collection)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(failed)?;
        match expected {
            Some(expected) => Err(dimension_mismatch(
                &what,
                record.embedding.len(),
                collection,
                expected,
            )),
            None => Err(Error::Unavailable(format!(
                "{OPERATION}: collection {collection} was removed at the same time"
            ))),
        }
    }

    /// Finds the nearest records. A collection that does not exist has no records.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`]: the query is empty, has a value that is not finite, or has
    /// a different number of dimensions than the collection.
    async fn search(
        &self,
        collection: &str,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorMatch>> {
        const OPERATION: &str = "search the vector records";
        check_embedding("the query", embedding)?;
        let Some(expected) = self.dimensions(OPERATION, collection).await? else {
            return Ok(Vec::new());
        };
        if usize::try_from(expected).ok() != Some(embedding.len()) {
            return Err(dimension_mismatch(
                "the query",
                embedding.len(),
                collection,
                expected,
            ));
        }
        let rows: Vec<(String, Vec<f32>, String, String, f32)> = sqlx::query_as(SEARCH)
            .bind(collection)
            .bind(embedding)
            .bind(sql_limit(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(|error| db_error(OPERATION, error))?;
        rows.into_iter()
            .map(|(id, embedding, content, metadata, score)| {
                match_from_row(id, embedding, content, &metadata, score)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn invalid_input(result: Result<i32>) -> String {
        match result {
            Err(Error::InvalidInput(message)) => message,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn a_good_embedding_gives_its_number_of_dimensions() {
        assert_eq!(check_embedding("the query", &[0.5, -1.0, 0.0]).unwrap(), 3);
        assert_eq!(
            check_embedding("the query", &vec![0.0; MAX_DIMENSIONS]).unwrap(),
            16_000
        );
    }

    #[test]
    fn an_empty_embedding_is_rejected() {
        assert_eq!(
            invalid_input(check_embedding("vector record a", &[])),
            "vectors: vector record a has an empty embedding"
        );
    }

    #[test]
    fn an_embedding_above_the_pgvector_limit_is_rejected() {
        let message = invalid_input(check_embedding("the query", &vec![0.0; MAX_DIMENSIONS + 1]));
        assert_eq!(
            message,
            "vectors: the query has 16001 dimensions, and the limit is 16000"
        );
    }

    #[test]
    fn values_that_are_not_finite_are_rejected_with_their_index() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let message = invalid_input(check_embedding("the query", &[1.0, 2.0, bad]));
            assert_eq!(
                message,
                "vectors: the query has a value at index 2 that is not a finite number"
            );
        }
    }

    #[test]
    fn a_dimension_mismatch_names_the_two_numbers() {
        let error = dimension_mismatch("the query", 3, "notes", 32);
        match error {
            Error::InvalidInput(message) => assert_eq!(
                message,
                "vectors: the query has 3 dimensions, but collection notes has 32"
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn a_row_maps_to_a_match() {
        let found = match_from_row(
            "burst".to_owned(),
            vec![0.6, 0.8],
            "sign-in burst".to_owned(),
            r#"{"source":"analyst","weight":0.25}"#,
            0.5,
        )
        .unwrap();
        assert_eq!(
            found,
            VectorMatch {
                record: VectorRecord {
                    id: "burst".to_owned(),
                    embedding: vec![0.6, 0.8],
                    text: "sign-in burst".to_owned(),
                    metadata: json!({ "source": "analyst", "weight": 0.25 }),
                },
                score: 0.5,
            }
        );
    }

    #[test]
    fn metadata_that_is_not_json_is_a_serialization_error() {
        let error = match_from_row("a".to_owned(), vec![1.0], String::new(), "{", 0.0).unwrap_err();
        assert!(
            matches!(&error, Error::Serialization(message) if message.contains("metadata")),
            "{error:?}"
        );
    }
}
