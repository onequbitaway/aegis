//! Tests of the vector store on pgvector.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use aegis_contracts::graph::{VectorMatch, VectorRecord, VectorStore};
use aegis_contracts::{Error, Result};
use aegis_testkit::{EMBEDDING_DIMENSIONS, MemoryVectors, embed_text};
use serde_json::json;

use crate::support::TestDb;

const NOTES: [(&str, &str); 3] = [
    ("burst", "sign-in burst from one address"),
    ("secret", "rotate the vault secret"),
    ("role", "application assigned a privileged role"),
];

fn note(id: &str, text: &str) -> VectorRecord {
    VectorRecord {
        id: id.to_owned(),
        embedding: embed_text(text),
        text: text.to_owned(),
        metadata: serde_json::Value::Null,
    }
}

fn record(id: &str, embedding: Vec<f32>) -> VectorRecord {
    VectorRecord {
        id: id.to_owned(),
        embedding,
        text: String::new(),
        metadata: serde_json::Value::Null,
    }
}

fn ids(matches: &[VectorMatch]) -> Vec<&str> {
    matches
        .iter()
        .map(|found| found.record.id.as_str())
        .collect()
}

fn invalid_input<T: std::fmt::Debug>(result: Result<T>) -> String {
    match result {
        Err(Error::InvalidInput(message)) => message,
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

/// The cosine similarity, as the in-memory store of the test kit computes it.
fn cosine(left: &[f32], right: &[f32]) -> f32 {
    let dot: f32 = left.iter().zip(right).map(|(a, b)| a * b).sum();
    let norm = |vector: &[f32]| vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    dot / (norm(left) * norm(right))
}

#[tokio::test]
async fn vector_search_returns_the_nearest_records_first() {
    let database = TestDb::new().await;
    let store = database.store.vectors();
    for (id, text) in NOTES {
        store.upsert("notes", note(id, text)).await.unwrap();
    }

    let query = embed_text("burst of sign-in attempts from an address");
    let matches = store.search("notes", &query, 2).await.unwrap();
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].record, note("burst", NOTES[0].1));
    assert!(matches[0].score > matches[1].score);
    assert_eq!(store.search("absent", &query, 2).await.unwrap(), Vec::new());
    assert_eq!(store.search("notes", &query, 0).await.unwrap(), Vec::new());
    assert_eq!(store.search("notes", &query, 100).await.unwrap().len(), 3);
}

#[tokio::test]
async fn the_score_is_the_cosine_similarity_and_the_order_is_the_order_of_the_test_kit() {
    let database = TestDb::new().await;
    let store = database.store.vectors();
    let memory = MemoryVectors::default();
    let texts = [
        ("a", "sign-in burst from one address"),
        ("b", "rotate the vault secret"),
        ("c", "application assigned a privileged role"),
        ("d", "a new credential on a service principal"),
        ("e", "sign-in from a new country"),
        ("f", "mailbox rule forwards mail to an external address"),
    ];
    for (id, text) in texts {
        store.upsert("notes", note(id, text)).await.unwrap();
        memory.upsert("notes", note(id, text)).await.unwrap();
    }

    let query = embed_text("sign-in from an address in a new country");
    assert_eq!(query.len(), EMBEDDING_DIMENSIONS);
    let found = store.search("notes", &query, 10).await.unwrap();
    let expected = memory.search("notes", &query, 10).await.unwrap();
    assert_eq!(found.len(), 6);
    assert_eq!(ids(&found), ids(&expected));
    for (found, expected) in found.iter().zip(&expected) {
        assert_eq!(found.record, expected.record);
        let similarity = cosine(&query, &found.record.embedding);
        assert!(
            (found.score - similarity).abs() < 1e-5,
            "{}: {} is not {similarity}",
            found.record.id,
            found.score
        );
        assert!((found.score - expected.score).abs() < 1e-5);
    }
    // The scores go down.
    assert!(found.windows(2).all(|pair| pair[0].score >= pair[1].score));
    // A record is its own nearest record, with the similarity 1.
    let own = store
        .search("notes", &embed_text(texts[3].1), 1)
        .await
        .unwrap();
    assert_eq!(ids(&own), ["d"]);
    assert!((own[0].score - 1.0).abs() < 1e-5, "{}", own[0].score);
}

#[tokio::test]
async fn vector_store_rejects_empty_and_mismatched_embeddings() {
    let database = TestDb::new().await;
    let store = database.store.vectors();

    let empty = invalid_input(store.upsert("notes", record("a", Vec::new())).await);
    assert_eq!(empty, "vectors: vector record a has an empty embedding");
    // The rejected record did not make the collection.
    assert_eq!(
        store.search("notes", &[1.0, 0.0, 0.0], 1).await.unwrap(),
        Vec::new()
    );

    store
        .upsert("notes", record("a", vec![1.0, 0.0]))
        .await
        .unwrap();
    let mismatch = invalid_input(store.search("notes", &[1.0, 0.0, 0.0], 1).await);
    assert_eq!(
        mismatch,
        "vectors: the query has 3 dimensions, but collection notes has 2"
    );
    let mismatch = invalid_input(
        store
            .upsert("notes", record("b", vec![1.0, 0.0, 0.0]))
            .await,
    );
    assert_eq!(
        mismatch,
        "vectors: vector record b has 3 dimensions, but collection notes has 2"
    );
    let empty_query = invalid_input(store.search("notes", &[], 1).await);
    assert_eq!(empty_query, "vectors: the query has an empty embedding");
    let not_finite = invalid_input(
        store
            .upsert("notes", record("c", vec![f32::NAN, 0.0]))
            .await,
    );
    assert_eq!(
        not_finite,
        "vectors: vector record c has a value at index 0 that is not a finite number"
    );

    // Only the good record is in the collection.
    let all = store.search("notes", &[1.0, 0.0], 10).await.unwrap();
    assert_eq!(ids(&all), ["a"]);
}

#[tokio::test]
async fn a_record_with_the_same_identifier_is_replaced() {
    let database = TestDb::new().await;
    let store = database.store.vectors();
    store
        .upsert("notes", record("a", vec![1.0, 0.0]))
        .await
        .unwrap();
    store
        .upsert("notes", record("b", vec![0.6, 0.8]))
        .await
        .unwrap();

    let replacement = VectorRecord {
        id: "a".to_owned(),
        embedding: vec![0.0, 1.0],
        text: "second version".to_owned(),
        metadata: json!({
            "source": "analyst",
            "weight": 0.1 + 0.2,
            "tags": ["x", null, 3],
            "nested": { "ratio": 2.5e-9 },
        }),
    };
    store.upsert("notes", replacement.clone()).await.unwrap();

    let all = store.search("notes", &[0.0, 1.0], 10).await.unwrap();
    assert_eq!(ids(&all), ["a", "b"]);
    assert_eq!(all[0].record, replacement);
    assert!((all[0].score - 1.0).abs() < 1e-6, "{}", all[0].score);
    assert!((all[1].score - 0.8).abs() < 1e-6, "{}", all[1].score);
}

#[tokio::test]
async fn collections_are_separate_and_can_have_different_dimensions() {
    let database = TestDb::new().await;
    let store = database.store.vectors();
    store
        .upsert("two", record("same-id", vec![1.0, 0.0]))
        .await
        .unwrap();
    store
        .upsert("three", record("same-id", vec![0.0, 0.0, 1.0]))
        .await
        .unwrap();

    let two = store.search("two", &[1.0, 0.0], 10).await.unwrap();
    assert_eq!(two.len(), 1);
    assert_eq!(two[0].record.embedding, [1.0, 0.0]);
    let three = store.search("three", &[0.0, 0.0, 1.0], 10).await.unwrap();
    assert_eq!(three.len(), 1);
    assert_eq!(three[0].record.embedding, [0.0, 0.0, 1.0]);
}

#[tokio::test]
async fn a_vector_of_zero_length_has_the_similarity_zero() {
    let database = TestDb::new().await;
    let store = database.store.vectors();
    store
        .upsert("notes", record("zero", vec![0.0, 0.0]))
        .await
        .unwrap();
    store
        .upsert("notes", record("opposite", vec![-1.0, 0.0]))
        .await
        .unwrap();
    store
        .upsert("notes", record("same", vec![2.0, 0.0]))
        .await
        .unwrap();

    let found = store.search("notes", &[1.0, 0.0], 10).await.unwrap();
    assert_eq!(ids(&found), ["same", "zero", "opposite"]);
    let scores: Vec<f32> = found.iter().map(|found| found.score).collect();
    assert_eq!(scores, [1.0, 0.0, -1.0]);

    // A query of zero length is not near any record. Each similarity is zero.
    let found = store.search("notes", &[0.0, 0.0], 10).await.unwrap();
    assert_eq!(ids(&found), ["opposite", "same", "zero"]);
    assert!(found.iter().all(|found| found.score == 0.0));
}

#[tokio::test]
async fn first_writes_at_the_same_time_give_the_collection_one_number_of_dimensions() {
    let database = TestDb::new().await;
    let stores = [database.store.clone(), database.second_store().await];
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..16_usize {
        let store = stores[index % 2].vectors();
        // The writers do not agree: 2 dimensions or 3 dimensions.
        let dimensions = 2 + index % 4 / 2;
        tasks.spawn(async move {
            let result = store
                .upsert("raced", record(&format!("r{index}"), vec![1.0; dimensions]))
                .await;
            (dimensions, result)
        });
    }
    let results = tokio::time::timeout(Duration::from_secs(120), tasks.join_all())
        .await
        .unwrap();
    assert_eq!(results.len(), 16);

    let winners: Vec<usize> = results
        .iter()
        .filter(|(_, result)| result.is_ok())
        .map(|(dimensions, _)| *dimensions)
        .collect();
    assert_eq!(winners.len(), 8, "{results:?}");
    let winner = winners[0];
    assert!(winners.iter().all(|dimensions| *dimensions == winner));
    for (dimensions, result) in results {
        if dimensions != winner {
            let message = invalid_input(result);
            assert!(
                message.ends_with(&format!(
                    "has {dimensions} dimensions, but collection raced has {winner}"
                )),
                "{message}"
            );
        }
    }
    let stored = stores[0]
        .vectors()
        .search("raced", &vec![1.0; winner], 100)
        .await
        .unwrap();
    assert_eq!(stored.len(), 8);
    assert!(
        stored
            .iter()
            .all(|found| found.record.embedding.len() == winner)
    );
}
