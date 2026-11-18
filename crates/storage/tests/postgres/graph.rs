//! Tests of the Defensive Graph on Apache AGE.
//!
//! The first four tests check the same behaviors as the tests of
//! `aegis_testkit::MemoryGraph`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::Duration;

use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::graph::{
    DefensiveGraph, Direction, GraphEdge, GraphNode, NodeId, NodeKind, relation,
};
use aegis_contracts::{Error, Result};
use aegis_storage::{MAX_NODE_ID_BYTES, PgGraph, PgStore};
use chrono::{TimeZone, Utc};
use serde_json::json;
use sqlx::{Connection, Executor};

use crate::support::{TestDb, config};

fn entity_node(kind: EntityKind, id: &str, age_seconds: i64) -> GraphNode {
    let mut node = GraphNode::from_entity(&EntityRef::new(kind, id));
    node.updated_at = Utc::now() - chrono::Duration::seconds(age_seconds);
    node
}

fn plain_node(id: &str) -> GraphNode {
    GraphNode {
        id: NodeId(id.to_owned()),
        kind: NodeKind::Asset,
        label: id.to_owned(),
        properties: BTreeMap::new(),
        updated_at: Utc.with_ymd_and_hms(2026, 3, 4, 5, 6, 7).unwrap(),
    }
}

/// Writes the graph of the test kit tests: user-1 -owns-> sp-1 -has_role-> global-admin.
async fn sample_graph(graph: &PgGraph) -> (NodeId, NodeId, NodeId) {
    let user = entity_node(EntityKind::User, "user-1", 30);
    let app = entity_node(EntityKind::ServicePrincipal, "sp-1", 10);
    let role = entity_node(EntityKind::Role, "global-admin", 20);
    let ids = (user.id.clone(), app.id.clone(), role.id.clone());
    for node in [user, app, role] {
        graph.upsert_node(node).await.unwrap();
    }
    graph
        .upsert_edge(GraphEdge::new(ids.0.clone(), relation::OWNS, ids.1.clone()))
        .await
        .unwrap();
    graph
        .upsert_edge(GraphEdge::new(
            ids.1.clone(),
            relation::HAS_ROLE,
            ids.2.clone(),
        ))
        .await
        .unwrap();
    ids
}

fn labels(nodes: &[GraphNode]) -> Vec<&str> {
    nodes.iter().map(|node| node.label.as_str()).collect()
}

fn invalid_input<T: std::fmt::Debug>(result: Result<T>) -> String {
    match result {
        Err(Error::InvalidInput(message)) => message,
        other => panic!("expected InvalidInput, got {other:?}"),
    }
}

#[tokio::test]
async fn neighbors_follow_the_direction_and_the_relation() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let (user, app, role) = sample_graph(&graph).await;

    let outgoing = graph
        .neighbors(&app, None, Direction::Outgoing)
        .await
        .unwrap();
    assert_eq!(labels(&outgoing), ["global-admin"]);
    let incoming = graph
        .neighbors(&app, None, Direction::Incoming)
        .await
        .unwrap();
    assert_eq!(labels(&incoming), ["user-1"]);
    let both = graph.neighbors(&app, None, Direction::Both).await.unwrap();
    assert_eq!(labels(&both), ["user-1", "global-admin"]);
    let filtered = graph
        .neighbors(&app, Some(relation::OWNS), Direction::Both)
        .await
        .unwrap();
    assert_eq!(labels(&filtered), ["user-1"]);
    let wrong_direction = graph
        .neighbors(&app, Some(relation::OWNS), Direction::Outgoing)
        .await
        .unwrap();
    assert_eq!(wrong_direction, Vec::new());
    assert_eq!(
        graph
            .neighbors(&user, None, Direction::Incoming)
            .await
            .unwrap(),
        Vec::new()
    );
    assert_eq!(
        graph.node(&role).await.unwrap().map(|node| node.kind),
        Some(NodeKind::Asset)
    );
}

#[tokio::test]
async fn an_edge_to_a_missing_node_is_rejected() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let (user, _, _) = sample_graph(&graph).await;
    let missing = NodeId("host:absent".to_owned());

    let error = graph
        .upsert_edge(GraphEdge::new(
            user.clone(),
            relation::ACTED_ON,
            missing.clone(),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::NotFound(message) if message == "graph node host:absent"),
        "{error:?}"
    );
    let error = graph
        .upsert_edge(GraphEdge::new(missing.clone(), relation::ACTED_ON, user))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::NotFound(message) if message == "graph node host:absent"),
        "{error:?}"
    );

    assert_eq!(graph.edge_count().await.unwrap(), 2);
    assert_eq!(graph.node_count().await.unwrap(), 3);
    assert_eq!(graph.node(&missing).await.unwrap(), None);
}

#[tokio::test]
async fn the_same_edge_and_node_are_replaced_and_not_duplicated() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let (user, app, _) = sample_graph(&graph).await;

    let mut edge = GraphEdge::new(user.clone(), relation::OWNS, app.clone());
    edge.properties.insert("since".to_owned(), "2026".into());
    graph.upsert_edge(edge.clone()).await.unwrap();
    assert_eq!(graph.edge_count().await.unwrap(), 2);
    assert_eq!(
        graph.edge(&user, relation::OWNS, &app).await.unwrap(),
        Some(edge)
    );
    // A second write replaces the properties. It does not merge them.
    let mut changed = GraphEdge::new(user.clone(), relation::OWNS, app.clone());
    changed
        .properties
        .insert("source".to_owned(), "audit".into());
    graph.upsert_edge(changed.clone()).await.unwrap();
    assert_eq!(graph.edge_count().await.unwrap(), 2);
    assert_eq!(
        graph.edge(&user, relation::OWNS, &app).await.unwrap(),
        Some(changed)
    );
    // The same two nodes can have a relation with a different name and a different direction.
    assert_eq!(
        graph.edge(&user, relation::HAS_ROLE, &app).await.unwrap(),
        None
    );
    assert_eq!(graph.edge(&app, relation::OWNS, &user).await.unwrap(), None);

    let mut renamed = entity_node(EntityKind::User, "user-1", 0);
    renamed.label = "Alice".to_owned();
    renamed.properties.remove("entity_kind");
    renamed
        .properties
        .insert("department".to_owned(), "finance".into());
    graph.upsert_node(renamed.clone()).await.unwrap();
    assert_eq!(graph.node_count().await.unwrap(), 3);
    assert_eq!(graph.node(&user).await.unwrap(), Some(renamed));
    // The relation of the replaced node stays.
    let owned = graph
        .neighbors(&user, None, Direction::Outgoing)
        .await
        .unwrap();
    assert_eq!(labels(&owned), ["sp-1"]);
}

#[tokio::test]
async fn nodes_by_kind_lists_newest_first_up_to_the_limit() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    sample_graph(&graph).await;

    let identities = graph.nodes_by_kind(NodeKind::Identity, 10).await.unwrap();
    assert_eq!(labels(&identities), ["sp-1", "user-1"]);
    let limited = graph.nodes_by_kind(NodeKind::Identity, 1).await.unwrap();
    assert_eq!(labels(&limited), ["sp-1"]);
    let assets = graph.nodes_by_kind(NodeKind::Asset, 10).await.unwrap();
    assert_eq!(labels(&assets), ["global-admin"]);
    assert_eq!(
        graph.nodes_by_kind(NodeKind::Incident, 10).await.unwrap(),
        Vec::new()
    );
    assert_eq!(
        graph.nodes_by_kind(NodeKind::Identity, 0).await.unwrap(),
        Vec::new()
    );

    // A node that changes moves to the front.
    let touched = entity_node(EntityKind::User, "user-1", 0);
    graph.upsert_node(touched).await.unwrap();
    let identities = graph.nodes_by_kind(NodeKind::Identity, 10).await.unwrap();
    assert_eq!(labels(&identities), ["user-1", "sp-1"]);
}

#[tokio::test]
async fn nodes_one_nanosecond_apart_are_in_time_order() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let base = Utc.with_ymd_and_hms(2026, 3, 4, 5, 6, 7).unwrap();
    for (id, nanoseconds) in [("b", 2), ("c", 3), ("a", 1)] {
        let mut node = plain_node(id);
        node.kind = NodeKind::Finding;
        node.updated_at = base + chrono::Duration::nanoseconds(nanoseconds);
        graph.upsert_node(node).await.unwrap();
    }
    let findings = graph.nodes_by_kind(NodeKind::Finding, 10).await.unwrap();
    assert_eq!(labels(&findings), ["c", "b", "a"]);
    assert_eq!(
        findings[0].updated_at,
        base + chrono::Duration::nanoseconds(3)
    );
}

#[tokio::test]
async fn a_node_and_a_relation_keep_each_property_value() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let properties: BTreeMap<String, serde_json::Value> = serde_json::from_value(json!({
        "text": "plain",
        "empty": "",
        "unicode": "Zoë \u{1F512} \u{05E9}\u{05DC}\u{05D5}\u{05DD}",
        "escapes": "line 1\nline 2\ttab \"quoted\" back\\slash",
        "yes": true,
        "no": false,
        "nothing": null,
        "count": 7,
        "negative": -42,
        "largest": i64::MAX,
        "smallest": i64::MIN,
        "sum": 0.1 + 0.2,
        "whole_float": 3.0,
        "large_float": 1e21,
        "small_float": 5e-324,
        "hard_to_parse": [1.071_566_039_146_582_6e-75, -1.603_964_615_428_183e143],
        "list": [1, 2.5, "x", null, [], {}],
        "nested": { "a": { "b": [{ "c": null }] } },
        "key with spaces and $signs": "ok",
    }))
    .unwrap();
    let node = GraphNode {
        id: NodeId("user:alice@example.com".to_owned()),
        kind: NodeKind::Identity,
        label: "Alice".to_owned(),
        properties: properties.clone(),
        updated_at: Utc.with_ymd_and_hms(2026, 3, 4, 5, 6, 7).unwrap()
            + chrono::Duration::nanoseconds(123_456_789),
    };
    graph.upsert_node(node.clone()).await.unwrap();
    assert_eq!(graph.node(&node.id).await.unwrap(), Some(node.clone()));
    assert_eq!(
        graph.nodes_by_kind(NodeKind::Identity, 5).await.unwrap(),
        vec![node.clone()]
    );

    let other = plain_node("host:h1");
    graph.upsert_node(other.clone()).await.unwrap();
    let edge = GraphEdge {
        from: node.id.clone(),
        to: other.id.clone(),
        relation: relation::ACTED_ON.to_owned(),
        properties,
    };
    graph.upsert_edge(edge.clone()).await.unwrap();
    assert_eq!(
        graph
            .edge(&node.id, relation::ACTED_ON, &other.id)
            .await
            .unwrap(),
        Some(edge)
    );
    assert_eq!(
        graph
            .neighbors(&other.id, None, Direction::Incoming)
            .await
            .unwrap(),
        vec![node]
    );
}

#[tokio::test]
async fn a_cypher_injection_attempt_is_stored_as_data_and_changes_nothing_else() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let (user, app, role) = sample_graph(&graph).await;
    let before = [
        graph.node(&user).await.unwrap().unwrap(),
        graph.node(&app).await.unwrap().unwrap(),
        graph.node(&role).await.unwrap().unwrap(),
    ];

    // Each text tries to end the value, the Cypher statement, or the SQL statement.
    let hostile = [
        "x'}) MATCH (m) DETACH DELETE m //",
        "x\"}) MATCH (m) DETACH DELETE m RETURN 1 //",
        "x` DETACH DELETE n",
        "$cypher$, NULL) AS (c0 ag_catalog.agtype); DROP SCHEMA aegis CASCADE; --",
        "$$; DELETE FROM aegis.audit_log; --",
        "'; DROP TABLE aegis.incidents; --",
        "$id",
        "\\'}) DETACH DELETE (n) //",
        "{id: 'user:user-1'}) SET n.label = 'owned' //",
    ];
    for (index, text) in hostile.iter().enumerate() {
        let node = GraphNode {
            id: NodeId((*text).to_owned()),
            kind: NodeKind::Finding,
            label: (*text).to_owned(),
            properties: BTreeMap::from([
                ("value".to_owned(), json!(text)),
                ((*text).to_owned(), json!([text, { "nested": text }])),
            ]),
            updated_at: Utc.with_ymd_and_hms(2026, 3, 4, 5, 6, 7).unwrap()
                + chrono::Duration::seconds(i64::try_from(index).unwrap()),
        };
        graph.upsert_node(node.clone()).await.unwrap();
        // The text is the identifier, the label, a key, and a value. Nothing ran.
        assert_eq!(graph.node(&node.id).await.unwrap(), Some(node.clone()));

        let mut edge = GraphEdge::new(user.clone(), relation::INVOLVES, node.id.clone());
        edge.properties.insert((*text).to_owned(), json!(text));
        graph.upsert_edge(edge.clone()).await.unwrap();
        assert_eq!(
            graph
                .edge(&user, relation::INVOLVES, &node.id)
                .await
                .unwrap(),
            Some(edge)
        );
        assert_eq!(
            graph
                .neighbors(&node.id, Some(relation::INVOLVES), Direction::Incoming)
                .await
                .unwrap(),
            vec![before[0].clone()]
        );
    }

    let count = u64::try_from(hostile.len()).unwrap();
    assert_eq!(graph.node_count().await.unwrap(), 3 + count);
    assert_eq!(graph.edge_count().await.unwrap(), 2 + count);
    let findings = graph.nodes_by_kind(NodeKind::Finding, 100).await.unwrap();
    let mut found: Vec<&str> = findings.iter().map(|node| node.id.0.as_str()).collect();
    found.reverse();
    assert_eq!(found, hostile);
    // The first three nodes and their relations are the same as before.
    assert_eq!(
        [
            graph.node(&user).await.unwrap().unwrap(),
            graph.node(&app).await.unwrap().unwrap(),
            graph.node(&role).await.unwrap().unwrap(),
        ],
        before
    );
    assert_eq!(
        labels(&graph.neighbors(&app, None, Direction::Both).await.unwrap()),
        ["user-1", "global-admin"]
    );
    // The tables that the texts name are still there.
    let mut sql = database.sql().await;
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_catalog.pg_tables \
         WHERE schemaname = 'aegis' AND tablename IN ('audit_log', 'incidents')",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    sql.close().await.unwrap();
    assert_eq!(tables, 2);
}

#[tokio::test]
async fn an_invalid_relation_name_is_rejected_and_changes_nothing() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let (user, app, _) = sample_graph(&graph).await;

    let names = [
        "owns]->(b) DETACH DELETE b //",
        "owns|has_role",
        "Owns",
        "has-role",
        "owns`",
        "",
        "owns; DROP SCHEMA aegis CASCADE",
        "x$cypher$",
    ];
    for name in names {
        let message = invalid_input(
            graph
                .upsert_edge(GraphEdge::new(user.clone(), name, app.clone()))
                .await,
        );
        assert!(message.contains("^[a-z][a-z0-9_]*$"), "{name:?}: {message}");
        let message = invalid_input(graph.neighbors(&user, Some(name), Direction::Both).await);
        assert!(message.contains("^[a-z][a-z0-9_]*$"), "{name:?}: {message}");
        let message = invalid_input(graph.edge(&user, name, &app).await);
        assert!(message.contains("^[a-z][a-z0-9_]*$"), "{name:?}: {message}");
    }

    assert_eq!(graph.node_count().await.unwrap(), 3);
    assert_eq!(graph.edge_count().await.unwrap(), 2);
    assert_eq!(
        labels(
            &graph
                .neighbors(&user, None, Direction::Outgoing)
                .await
                .unwrap()
        ),
        ["sp-1"]
    );
}

#[tokio::test]
async fn a_relation_name_outside_the_contract_list_works_in_each_process() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let (user, app, role) = sample_graph(&graph).await;

    // A valid name that no relation has yet: the query finds nothing and does not fail.
    assert_eq!(
        graph
            .neighbors(&user, Some("reported_by"), Direction::Both)
            .await
            .unwrap(),
        Vec::new()
    );
    assert_eq!(graph.edge(&user, "reported_by", &app).await.unwrap(), None);

    graph
        .upsert_edge(GraphEdge::new(user.clone(), "reported_by", app.clone()))
        .await
        .unwrap();
    // A second process did not make the label. It can write the same name.
    let second = database.second_store().await.graph();
    second
        .upsert_edge(GraphEdge::new(user.clone(), "reported_by", role.clone()))
        .await
        .unwrap();
    second
        .upsert_edge(GraphEdge::new(user.clone(), "reported_by", app.clone()))
        .await
        .unwrap();

    assert_eq!(graph.edge_count().await.unwrap(), 4);
    let reported = graph
        .neighbors(&user, Some("reported_by"), Direction::Outgoing)
        .await
        .unwrap();
    assert_eq!(labels(&reported), ["sp-1", "global-admin"]);
}

#[tokio::test]
async fn neighbors_are_in_the_order_of_the_first_write_and_have_no_duplicates() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    for id in ["hub", "a", "b", "c"] {
        graph.upsert_node(plain_node(id)).await.unwrap();
    }
    let id = |text: &str| NodeId(text.to_owned());

    graph
        .upsert_edge(GraphEdge::new(id("hub"), relation::OWNS, id("c")))
        .await
        .unwrap();
    graph
        .upsert_edge(GraphEdge::new(id("a"), relation::ACTED_ON, id("hub")))
        .await
        .unwrap();
    graph
        .upsert_edge(GraphEdge::new(id("hub"), relation::INVOLVES, id("b")))
        .await
        .unwrap();
    // A second relation to a node that is already a neighbor.
    graph
        .upsert_edge(GraphEdge::new(id("hub"), relation::INVOLVES, id("c")))
        .await
        .unwrap();
    // A relation from the node to itself.
    graph
        .upsert_edge(GraphEdge::new(id("hub"), relation::MEMBER_OF, id("hub")))
        .await
        .unwrap();
    // A second write of the first relation does not move it.
    graph
        .upsert_edge(GraphEdge::new(id("hub"), relation::OWNS, id("c")))
        .await
        .unwrap();

    assert_eq!(graph.edge_count().await.unwrap(), 5);
    let both = graph
        .neighbors(&id("hub"), None, Direction::Both)
        .await
        .unwrap();
    assert_eq!(labels(&both), ["c", "a", "b", "hub"]);
    let outgoing = graph
        .neighbors(&id("hub"), None, Direction::Outgoing)
        .await
        .unwrap();
    assert_eq!(labels(&outgoing), ["c", "b", "hub"]);
    let incoming = graph
        .neighbors(&id("hub"), None, Direction::Incoming)
        .await
        .unwrap();
    assert_eq!(labels(&incoming), ["a", "hub"]);
    let involved = graph
        .neighbors(&id("hub"), Some(relation::INVOLVES), Direction::Both)
        .await
        .unwrap();
    assert_eq!(labels(&involved), ["b", "c"]);
}

#[tokio::test]
async fn a_node_that_does_not_exist_has_no_data_and_no_neighbors() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    let absent = NodeId("host:absent".to_owned());
    assert_eq!(graph.node(&absent).await.unwrap(), None);
    for direction in [Direction::Outgoing, Direction::Incoming, Direction::Both] {
        assert_eq!(
            graph.neighbors(&absent, None, direction).await.unwrap(),
            Vec::new()
        );
    }
    assert_eq!(graph.node_count().await.unwrap(), 0);
    assert_eq!(graph.edge_count().await.unwrap(), 0);
}

#[tokio::test]
async fn values_that_the_graph_cannot_hold_are_rejected_before_any_write() {
    let database = TestDb::new().await;
    let graph = database.store.graph();

    let mut too_large = plain_node("host:h1");
    too_large
        .properties
        .insert("bytes".to_owned(), json!(u64::MAX));
    let message = invalid_input(graph.upsert_node(too_large).await);
    assert!(message.contains("18446744073709551615"), "{message}");

    let mut nul = plain_node("host:h2");
    nul.label = "h\0".to_owned();
    let message = invalid_input(graph.upsert_node(nul).await);
    assert!(message.contains("U+0000"), "{message}");

    let long = plain_node(&"x".repeat(MAX_NODE_ID_BYTES + 1));
    let message = invalid_input(graph.upsert_node(long).await);
    assert!(message.contains("1025 bytes"), "{message}");

    assert_eq!(graph.node_count().await.unwrap(), 0);

    // The longest identifier is accepted.
    let longest = plain_node(&"x".repeat(MAX_NODE_ID_BYTES));
    graph.upsert_node(longest.clone()).await.unwrap();
    assert_eq!(graph.node(&longest.id).await.unwrap(), Some(longest));
}

#[tokio::test]
async fn writes_of_the_same_node_and_relation_at_the_same_time_make_one_of_each() {
    let database = TestDb::new().await;
    let stores = [database.store.clone(), database.second_store().await];
    for id in ["from", "to"] {
        stores[0].graph().upsert_node(plain_node(id)).await.unwrap();
    }

    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..24_usize {
        let graph = stores[index % 2].graph();
        tasks.spawn(async move {
            let mut node = plain_node("shared");
            node.label = format!("writer {index}");
            graph.upsert_node(node).await?;
            // A relation name that no process made before.
            let mut edge = GraphEdge::new(
                NodeId("from".to_owned()),
                "raced_with",
                NodeId("to".to_owned()),
            );
            edge.properties.insert("writer".to_owned(), json!(index));
            graph.upsert_edge(edge).await
        });
    }
    let results = tokio::time::timeout(Duration::from_secs(120), tasks.join_all())
        .await
        .unwrap();
    assert_eq!(results.len(), 24);
    for result in results {
        result.unwrap();
    }

    let graph = stores[0].graph();
    assert_eq!(graph.node_count().await.unwrap(), 3);
    assert_eq!(graph.edge_count().await.unwrap(), 1);
    let shared = graph
        .node(&NodeId("shared".to_owned()))
        .await
        .unwrap()
        .unwrap();
    assert!(shared.label.starts_with("writer "), "{}", shared.label);
    let edge = graph
        .edge(
            &NodeId("from".to_owned()),
            "raced_with",
            &NodeId("to".to_owned()),
        )
        .await
        .unwrap()
        .unwrap();
    let writer = edge.properties["writer"].as_u64().unwrap();
    assert!(writer < 24, "{writer}");
}

#[tokio::test]
async fn a_write_at_the_same_time_as_a_client_without_the_lock_is_a_retryable_error() {
    let database = TestDb::new().await;
    let graph = database.store.graph();
    for id in ["a", "b"] {
        graph.upsert_node(plain_node(id)).await.unwrap();
    }

    // A client that does not use the store makes a node and a relation, and does not
    // commit them yet.
    let mut other = database.sql().await;
    other.execute("LOAD 'age'").await.unwrap();
    other
        .execute(r#"SET search_path = "$user", public, ag_catalog"#)
        .await
        .unwrap();
    other.execute("BEGIN").await.unwrap();
    other
        .execute(
            "SELECT * FROM ag_catalog.cypher('aegis_graph', $$ \
             CREATE (:Node {id: 'c', kind: 'asset', label: 'other client', \
                 updated_at: '2026-01-01T00:00:00.000000000Z', props: {}}) \
             $$) AS (result ag_catalog.agtype)",
        )
        .await
        .unwrap();
    other
        .execute(
            "SELECT * FROM ag_catalog.cypher('aegis_graph', $$ \
             MATCH (a:Node {id: 'a'}), (b:Node {id: 'b'}) \
             CREATE (a)-[:owns {props: {}, created_at: '2026-01-01T00:00:00.000000000Z'}]->(b) \
             $$) AS (result ag_catalog.agtype)",
        )
        .await
        .unwrap();

    // The store writes the same node and the same relation. The unique indexes make the
    // two writes wait for the other client.
    let node_write = tokio::spawn({
        let graph = graph.clone();
        async move { graph.upsert_node(plain_node("c")).await }
    });
    let edge_write = tokio::spawn({
        let graph = graph.clone();
        async move {
            let edge = GraphEdge::new(
                NodeId("a".to_owned()),
                relation::OWNS,
                NodeId("b".to_owned()),
            );
            graph.upsert_edge(edge).await
        }
    });
    database.wait_for_blocked_sessions(2).await;
    assert!(!node_write.is_finished());
    assert!(!edge_write.is_finished());
    other.execute("COMMIT").await.unwrap();
    other.close().await.unwrap();

    let node_error = tokio::time::timeout(Duration::from_secs(60), node_write)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(&node_error, Error::Unavailable(message) if message == "write the graph node: a different client wrote the same item at the same time"),
        "{node_error:?}"
    );
    assert!(node_error.is_retryable());
    let edge_error = tokio::time::timeout(Duration::from_secs(60), edge_write)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(&edge_error, Error::Unavailable(message) if message == "write the graph relation: a different client wrote the same item at the same time"),
        "{edge_error:?}"
    );

    // The retry replaces the node and the relation of the other client.
    graph.upsert_node(plain_node("c")).await.unwrap();
    let mut edge = GraphEdge::new(
        NodeId("a".to_owned()),
        relation::OWNS,
        NodeId("b".to_owned()),
    );
    edge.properties.insert("source".to_owned(), json!("store"));
    graph.upsert_edge(edge.clone()).await.unwrap();
    assert_eq!(graph.node_count().await.unwrap(), 3);
    assert_eq!(graph.edge_count().await.unwrap(), 1);
    assert_eq!(
        graph.node(&NodeId("c".to_owned())).await.unwrap(),
        Some(plain_node("c"))
    );
    assert_eq!(
        graph
            .edge(
                &NodeId("a".to_owned()),
                relation::OWNS,
                &NodeId("b".to_owned())
            )
            .await
            .unwrap(),
        Some(edge)
    );
}

#[tokio::test]
async fn a_read_finds_a_relation_name_that_a_different_process_made_after_the_first_read() {
    let database = TestDb::new().await;
    let (user, app, _) = sample_graph(&database.store.graph()).await;

    // One connection, so each read uses the same session and the same prepared statements.
    let mut settings = config(&database.url(&[]));
    settings.max_connections = 1;
    let graph = PgStore::connect(&settings).await.unwrap().graph();

    // No relation has this name yet. The session prepares its statements now.
    for direction in [Direction::Outgoing, Direction::Incoming, Direction::Both] {
        assert_eq!(
            graph
                .neighbors(&user, Some("seen_with"), direction)
                .await
                .unwrap(),
            Vec::new()
        );
    }
    assert_eq!(graph.edge(&user, "seen_with", &app).await.unwrap(), None);
    assert_eq!(
        labels(&graph.neighbors(&user, None, Direction::Both).await.unwrap()),
        ["sp-1"]
    );
    assert_eq!(graph.edge_count().await.unwrap(), 2);

    // A different process makes the name and a relation with it.
    let edge = GraphEdge::new(user.clone(), "seen_with", app.clone());
    database
        .second_store()
        .await
        .graph()
        .upsert_edge(edge.clone())
        .await
        .unwrap();

    // The same session finds the relation with the same statements.
    assert_eq!(
        labels(
            &graph
                .neighbors(&user, Some("seen_with"), Direction::Outgoing)
                .await
                .unwrap()
        ),
        ["sp-1"]
    );
    assert_eq!(
        labels(
            &graph
                .neighbors(&app, Some("seen_with"), Direction::Incoming)
                .await
                .unwrap()
        ),
        ["user-1"]
    );
    assert_eq!(
        labels(
            &graph
                .neighbors(&user, Some("seen_with"), Direction::Both)
                .await
                .unwrap()
        ),
        ["sp-1"]
    );
    assert_eq!(
        graph.edge(&user, "seen_with", &app).await.unwrap(),
        Some(edge)
    );
    assert_eq!(graph.edge_count().await.unwrap(), 3);
    // The session also writes with the name. It did not make the label itself.
    let mut changed = GraphEdge::new(user.clone(), "seen_with", app.clone());
    changed.properties.insert("times".to_owned(), json!(2));
    graph.upsert_edge(changed.clone()).await.unwrap();
    assert_eq!(
        graph.edge(&user, "seen_with", &app).await.unwrap(),
        Some(changed)
    );
    assert_eq!(graph.edge_count().await.unwrap(), 3);
}
