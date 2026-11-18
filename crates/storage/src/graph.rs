//! The Defensive Graph on Apache AGE.
//!
//! # Data model
//!
//! The graph `aegis_graph` has one vertex label, `Node`. A vertex has these properties:
//!
//! | Property | Contents |
//! | --- | --- |
//! | `id` | The node identifier. A unique index permits one vertex for each identifier. |
//! | `kind` | The node type, for example `identity`. |
//! | `label` | The display name. |
//! | `updated_at` | The time of the last change, as fixed-width RFC 3339 text in UTC. |
//! | `props` | The properties of the node, as a map. |
//!
//! Each relation name is one edge label. An edge has the properties `props` (a map) and
//! `created_at` (the time of the first write, same format as `updated_at`).
//!
//! # Statements
//!
//! Each statement is openCypher through the `cypher()` function of Apache AGE. All values go
//! in the `agtype` parameter map of the call. A relation name is the only text that goes
//! into a statement, because Cypher does not let a label be a parameter. [`RelationLabel`]
//! is the only way to get a relation name into a statement, and it accepts only names that
//! match `^[a-z][a-z0-9_]*$`.
//!
//! # Writes at the same time
//!
//! Apache AGE fails a statement that changes a vertex or an edge which a different session
//! changes at the same time. Thus each write runs in a transaction that first takes an
//! advisory lock for the node or for the relation. The lock is in the database, so the
//! writes of all processes to one node or one relation run one after the other. Writes to
//! different nodes and relations do not wait.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use aegis_contracts::graph::{DefensiveGraph, Direction, GraphEdge, GraphNode, NodeId, NodeKind};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Datelike, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnection, PgPool, Postgres};
use sqlx::{AssertSqlSafe, Transaction};

use crate::agtype::Agtype;
use crate::error::{UNIQUE_VIOLATION, db_error, decode_error, sqlstate};
use crate::json::{sql_limit, variant_name};
use crate::store::RelationCache;

/// The largest size of a node identifier, in bytes.
pub const MAX_NODE_ID_BYTES: usize = 1024;

/// The largest size of a relation name, in bytes.
pub const MAX_RELATION_NAME_BYTES: usize = 48;

/// How many times a relation write runs again after a different session made a missing
/// end node at the same time.
const WRITE_ATTEMPTS: usize = 3;

/// The first key of the advisory lock for the write of one node. The second key is a hash
/// of the node identifier. The value is the ASCII text `aegn`.
const NODE_LOCK_SPACE: i32 = 0x6165_676E;

/// The first key of the advisory lock for the write of one relation. The second key is a
/// hash of the start, the name, and the end. The value is the ASCII text `aege`.
const EDGE_LOCK_SPACE: i32 = 0x6165_6765;

/// Starts the transaction of a write.
///
/// With this isolation level, the statement after the lock sees each change that a
/// different session committed while this session waited for the lock.
const BEGIN_WRITE: &str = "BEGIN ISOLATION LEVEL READ COMMITTED";

/// Takes the lock of a write. A hash collision makes two writes wait, and nothing more.
const LOCK_WRITE: &str = "SELECT pg_catalog.pg_advisory_xact_lock($1, pg_catalog.hashtext($2))";

/// Makes the SQL text of one `cypher()` call. All parts are literals of this file.
macro_rules! cypher {
    (select: $select:literal, columns: $columns:literal, $body:literal) => {
        concat!(
            "SELECT ",
            $select,
            " FROM ag_catalog.cypher('aegis_graph', $cypher$ ",
            $body,
            " $cypher$, $1) AS (",
            $columns,
            ")"
        )
    };
}

/// The output of a statement that returns one value: the text form of the `agtype` value.
macro_rules! one_value {
    ($body:literal) => {
        cypher!(
            select: "ag_catalog.agtype_out(c0)::text",
            columns: "c0 ag_catalog.agtype",
            $body
        )
    };
}

/// The output of a neighbor statement: the node, the time of the relation, the edge number.
macro_rules! neighbor_rows {
    ($body:literal) => {
        cypher!(
            select: "ag_catalog.agtype_out(c0)::text, ag_catalog.agtype_out(c1)::text, c2::bigint",
            columns: "c0 ag_catalog.agtype, c1 ag_catalog.agtype, c2 ag_catalog.agtype",
            $body
        )
    };
}

const READ_NODE: &str = one_value!("MATCH (n:Node) WHERE n.id = $id RETURN properties(n)");

const UPDATE_NODE: &str = one_value!(
    "MATCH (n:Node) WHERE n.id = $id \
     SET n.kind = $kind, n.label = $label, n.updated_at = $updated_at, n.props = $props \
     RETURN id(n)"
);

const CREATE_NODE: &str = one_value!(
    "CREATE (n:Node {id: $id, kind: $kind, label: $label, updated_at: $updated_at, props: $props}) \
     RETURN id(n)"
);

const EXISTING_NODE_IDS: &str = one_value!("MATCH (n:Node) WHERE n.id IN $ids RETURN n.id");

const COUNT_NODES: &str = one_value!("MATCH (n:Node) RETURN count(n)");

const COUNT_EDGES: &str = one_value!("MATCH (:Node)-[r]->(:Node) RETURN count(r)");

const NODES_BY_KIND: &str = concat!(
    "SELECT ag_catalog.agtype_out(c0)::text",
    " FROM ag_catalog.cypher('aegis_graph', $cypher$ ",
    "MATCH (n:Node) WHERE n.kind = $kind RETURN properties(n), n.updated_at, n.id",
    " $cypher$, $1) AS (c0 ag_catalog.agtype, c1 ag_catalog.agtype, c2 ag_catalog.agtype)",
    " ORDER BY c1 DESC, c2 ASC LIMIT $2"
);

const NEIGHBORS_OUT: &str = neighbor_rows!(
    "MATCH (n:Node)-[r]->(m:Node) WHERE n.id = $id RETURN properties(m), r.created_at, id(r)"
);

const NEIGHBORS_IN: &str = neighbor_rows!(
    "MATCH (n:Node)<-[r]-(m:Node) WHERE n.id = $id RETURN properties(m), r.created_at, id(r)"
);

const ENSURE_RELATION: &str = "SELECT aegis.ensure_relation($1)";

/// A relation name that is safe to use as an edge label in a Cypher statement.
///
/// The only constructor is [`RelationLabel::parse`]. A value thus always matches
/// `^[a-z][a-z0-9_]*$` and has at most [`MAX_RELATION_NAME_BYTES`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelationLabel<'a>(&'a str);

impl<'a> RelationLabel<'a> {
    /// Checks a relation name.
    pub(crate) fn parse(name: &'a str) -> Result<Self> {
        let mut bytes = name.bytes();
        let first_is_letter = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
        let rest_is_valid =
            bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !first_is_letter || !rest_is_valid || name.len() > MAX_RELATION_NAME_BYTES {
            return Err(Error::InvalidInput(format!(
                "graph: a relation name must match ^[a-z][a-z0-9_]*$ and have at most \
                 {MAX_RELATION_NAME_BYTES} characters"
            )));
        }
        Ok(Self(name))
    }

    pub(crate) fn as_str(self) -> &'a str {
        self.0
    }
}

/// Makes the statement that writes one relation with the label `relation`.
fn upsert_edge_statement(relation: RelationLabel<'_>) -> String {
    format!(
        "SELECT ag_catalog.agtype_out(c0)::text \
         FROM ag_catalog.cypher('aegis_graph', $cypher$ \
         MATCH (a:Node), (b:Node) WHERE a.id = $from AND b.id = $to \
         MERGE (a)-[r:{label}]->(b) \
         SET r.props = $props, r.created_at = coalesce(r.created_at, $now) \
         RETURN id(r) \
         $cypher$, $1) AS (c0 ag_catalog.agtype)",
        label = relation.as_str()
    )
}

/// Makes the statement that reads one relation with the label `relation`.
fn read_edge_statement(relation: RelationLabel<'_>) -> String {
    format!(
        "SELECT ag_catalog.agtype_out(c0)::text \
         FROM ag_catalog.cypher('aegis_graph', $cypher$ \
         MATCH (a:Node)-[r:{label}]->(b:Node) WHERE a.id = $from AND b.id = $to \
         RETURN r.props \
         $cypher$, $1) AS (c0 ag_catalog.agtype)",
        label = relation.as_str()
    )
}

/// Makes the statement that lists the neighbors of a node in one direction.
///
/// `outgoing` selects the relations that start at the node.
fn neighbors_statement(relation: Option<RelationLabel<'_>>, outgoing: bool) -> String {
    let Some(relation) = relation else {
        return if outgoing {
            NEIGHBORS_OUT
        } else {
            NEIGHBORS_IN
        }
        .to_owned();
    };
    let pattern = if outgoing {
        format!("(n:Node)-[r:{}]->(m:Node)", relation.as_str())
    } else {
        format!("(n:Node)<-[r:{}]-(m:Node)", relation.as_str())
    };
    format!(
        "SELECT ag_catalog.agtype_out(c0)::text, ag_catalog.agtype_out(c1)::text, c2::bigint \
         FROM ag_catalog.cypher('aegis_graph', $cypher$ \
         MATCH {pattern} WHERE n.id = $id RETURN properties(m), r.created_at, id(r) \
         $cypher$, $1) AS (c0 ag_catalog.agtype, c1 ag_catalog.agtype, c2 ag_catalog.agtype)"
    )
}

/// Makes the statement that lists the neighbors of a node for a direction.
///
/// For [`Direction::Both`], the statement is the union of the two directions. One
/// statement reads one consistent state of the graph.
fn neighbors_sql(relation: Option<RelationLabel<'_>>, direction: Direction) -> String {
    match direction {
        Direction::Outgoing => neighbors_statement(relation, true),
        Direction::Incoming => neighbors_statement(relation, false),
        Direction::Both => format!(
            "{} UNION ALL {}",
            neighbors_statement(relation, true),
            neighbors_statement(relation, false)
        ),
    }
}

/// Formats a time for the graph: RFC 3339 in UTC with nine fraction digits.
///
/// The fixed width makes the text order equal to the time order.
fn graph_time(time: DateTime<Utc>) -> Result<String> {
    if !(0..=9999).contains(&time.year()) {
        return Err(Error::InvalidInput(format!(
            "graph: the year {} is not in the range 0 to 9999",
            time.year()
        )));
    }
    Ok(time.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string())
}

fn check_node_id(id: &NodeId) -> Result<()> {
    if id.0.len() > MAX_NODE_ID_BYTES {
        return Err(Error::InvalidInput(format!(
            "graph: a node identifier has {} bytes, and the limit is {MAX_NODE_ID_BYTES}",
            id.0.len()
        )));
    }
    Ok(())
}

/// Makes the parameter map for a node write.
fn node_parameters(node: &GraphNode) -> Result<Agtype> {
    check_node_id(&node.id)?;
    Agtype::parameters(&json!({
        "id": node.id.0,
        "kind": variant_name(&node.kind)?,
        "label": node.label,
        "updated_at": graph_time(node.updated_at)?,
        "props": node.properties,
    }))
}

/// Makes the parameter map for a relation write.
fn edge_parameters(edge: &GraphEdge, now: DateTime<Utc>) -> Result<Agtype> {
    check_node_id(&edge.from)?;
    check_node_id(&edge.to)?;
    Agtype::parameters(&json!({
        "from": edge.from.0,
        "to": edge.to.0,
        "props": edge.properties,
        "now": graph_time(now)?,
    }))
}

/// Makes the text that identifies a relation for its write lock.
///
/// The length of the start identifier makes the text different for each relation.
fn edge_lock_key(edge: &GraphEdge, relation: RelationLabel<'_>) -> String {
    format!(
        "{}:{}>{}>{}",
        edge.from.0.len(),
        edge.from.0,
        relation.as_str(),
        edge.to.0
    )
}

/// Maps the failure of a graph write.
///
/// The write lock stops two stores that make the same node or the same relation at the
/// same time. A client that does not take the lock can still do that. The unique index
/// then rejects the second write, and a retry succeeds.
fn write_error(operation: &str, error: sqlx::Error) -> Error {
    if sqlstate(&error).as_deref() == Some(UNIQUE_VIOLATION) {
        return Error::Unavailable(format!(
            "{operation}: a different client wrote the same item at the same time"
        ));
    }
    db_error(operation, error)
}

/// A vertex as the graph stores it.
#[derive(Debug, Deserialize)]
struct StoredNode {
    id: String,
    kind: NodeKind,
    label: String,
    updated_at: DateTime<Utc>,
    #[serde(default)]
    props: BTreeMap<String, Value>,
}

/// Reads a node from the text form of its vertex properties.
fn node_from_text(text: &str) -> Result<GraphNode> {
    let stored: StoredNode =
        serde_json::from_str(text).map_err(|error| decode_error("a graph node", error))?;
    Ok(GraphNode {
        id: NodeId(stored.id),
        kind: stored.kind,
        label: stored.label,
        properties: stored.props,
        updated_at: stored.updated_at,
    })
}

/// Reads a text value from the text form of an `agtype` string.
fn string_from_text(what: &str, text: &str) -> Result<String> {
    serde_json::from_str(text).map_err(|error| decode_error(what, error))
}

/// Reads a count from the text form of an `agtype` integer.
fn count_from_text(text: &str) -> Result<u64> {
    serde_json::from_str(text).map_err(|error| decode_error("a graph count", error))
}

/// One row of a neighbor statement.
#[derive(Debug)]
struct NeighborRow {
    /// The text form of the vertex properties.
    node: String,
    /// The text form of the time of the first write of the relation.
    created_at: Option<String>,
    /// The number that Apache AGE gives to the edge.
    edge: i64,
}

/// Puts neighbor rows in the order of the first write of their relations, and keeps the
/// first row of each node.
fn neighbors_from_rows(mut rows: Vec<NeighborRow>) -> Result<Vec<GraphNode>> {
    rows.sort_by(|left, right| {
        (left.created_at.as_deref(), left.edge).cmp(&(right.created_at.as_deref(), right.edge))
    });
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    for row in &rows {
        let node = node_from_text(&row.node)?;
        if seen.insert(node.id.clone()) {
            nodes.push(node);
        }
    }
    Ok(nodes)
}

/// The Defensive Graph in the Apache AGE graph `aegis_graph`.
///
/// Get a value from [`PgStore::graph`](crate::PgStore::graph).
#[derive(Debug, Clone)]
pub struct PgGraph {
    pool: PgPool,
    relations: Arc<RelationCache>,
}

impl PgGraph {
    pub(crate) fn new(pool: PgPool, relations: Arc<RelationCache>) -> Self {
        Self { pool, relations }
    }

    /// Returns the number of nodes.
    pub async fn node_count(&self) -> Result<u64> {
        self.count("count the graph nodes", COUNT_NODES).await
    }

    /// Returns the number of relations.
    pub async fn edge_count(&self) -> Result<u64> {
        self.count("count the graph relations", COUNT_EDGES).await
    }

    /// Reads one relation. Returns `None` if the relation does not exist.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`]: the relation name does not match `^[a-z][a-z0-9_]*$`.
    pub async fn edge(
        &self,
        from: &NodeId,
        relation: &str,
        to: &NodeId,
    ) -> Result<Option<GraphEdge>> {
        const OPERATION: &str = "read the graph relation";
        let label = RelationLabel::parse(relation)?;
        let parameters = Agtype::parameters(&json!({ "from": from.0, "to": to.0 }))?;
        let row: Option<(Option<String>,)> =
            sqlx::query_as(AssertSqlSafe(read_edge_statement(label)))
                .bind(parameters)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| db_error(OPERATION, error))?;
        let Some((props,)) = row else {
            return Ok(None);
        };
        let properties = match props {
            Some(text) => serde_json::from_str(&text)
                .map_err(|error| decode_error("a graph relation", error))?,
            None => BTreeMap::new(),
        };
        Ok(Some(GraphEdge {
            from: from.clone(),
            to: to.clone(),
            relation: relation.to_owned(),
            properties,
        }))
    }

    async fn count(&self, operation: &str, statement: &'static str) -> Result<u64> {
        let (text,): (String,) = sqlx::query_as(statement)
            .bind(Agtype::parameters(&json!({}))?)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| db_error(operation, error))?;
        count_from_text(&text)
    }

    /// Makes the edge label for a relation name, with its unique index.
    ///
    /// The store remembers each name, so the database does this work one time for each
    /// name and each process.
    async fn ensure_relation(&self, relation: RelationLabel<'_>) -> Result<()> {
        if self.relations.contains(relation.as_str()) {
            return Ok(());
        }
        sqlx::query(ENSURE_RELATION)
            .bind(relation.as_str())
            .execute(&self.pool)
            .await
            .map_err(|error| db_error("prepare the graph relation", error))?;
        self.relations.insert(relation.as_str());
        Ok(())
    }

    /// Starts the transaction of a write and takes the lock for `key`.
    async fn begin_write(
        &self,
        operation: &str,
        space: i32,
        key: &str,
    ) -> Result<Transaction<'static, Postgres>> {
        let mut transaction = self
            .pool
            .begin_with(BEGIN_WRITE)
            .await
            .map_err(|error| db_error(operation, error))?;
        sqlx::query(LOCK_WRITE)
            .bind(space)
            .bind(key)
            .execute(&mut *transaction)
            .await
            .map_err(|error| db_error(operation, error))?;
        Ok(transaction)
    }
}

/// Returns which of `ids` are identifiers of nodes in the graph.
async fn existing_ids(connection: &mut PgConnection, ids: &[&NodeId]) -> Result<HashSet<String>> {
    let ids: Vec<&str> = ids.iter().map(|id| id.0.as_str()).collect();
    let rows: Vec<(String,)> = sqlx::query_as(EXISTING_NODE_IDS)
        .bind(Agtype::parameters(&json!({ "ids": ids }))?)
        .fetch_all(connection)
        .await
        .map_err(|error| db_error("read the graph nodes", error))?;
    rows.iter()
        .map(|(text,)| string_from_text("a graph node identifier", text))
        .collect()
}

#[async_trait]
impl DefensiveGraph for PgGraph {
    async fn upsert_node(&self, node: GraphNode) -> Result<()> {
        const OPERATION: &str = "write the graph node";
        let parameters = node_parameters(&node)?;
        let mut transaction = self
            .begin_write(OPERATION, NODE_LOCK_SPACE, &node.id.0)
            .await?;
        let updated: Vec<(String,)> = sqlx::query_as(UPDATE_NODE)
            .bind(&parameters)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| write_error(OPERATION, error))?;
        if updated.is_empty() {
            sqlx::query(CREATE_NODE)
                .bind(&parameters)
                .execute(&mut *transaction)
                .await
                .map_err(|error| write_error(OPERATION, error))?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db_error(OPERATION, error))
    }

    async fn upsert_edge(&self, edge: GraphEdge) -> Result<()> {
        const OPERATION: &str = "write the graph relation";
        let label = RelationLabel::parse(&edge.relation)?;
        let parameters = edge_parameters(&edge, Utc::now())?;
        self.ensure_relation(label).await?;
        let statement = upsert_edge_statement(label);
        let mut transaction = self
            .begin_write(OPERATION, EDGE_LOCK_SPACE, &edge_lock_key(&edge, label))
            .await?;
        for _ in 0..WRITE_ATTEMPTS {
            let written: Vec<(String,)> = sqlx::query_as(AssertSqlSafe(statement.as_str()))
                .bind(&parameters)
                .fetch_all(&mut *transaction)
                .await
                .map_err(|error| write_error(OPERATION, error))?;
            if !written.is_empty() {
                return transaction
                    .commit()
                    .await
                    .map_err(|error| db_error(OPERATION, error));
            }
            // No row: the start node or the end node does not exist.
            let existing = existing_ids(&mut transaction, &[&edge.from, &edge.to]).await?;
            for id in [&edge.from, &edge.to] {
                if !existing.contains(&id.0) {
                    return Err(Error::NotFound(format!("graph node {id}")));
                }
            }
            // A different session made the missing node in the meantime. Write again.
        }
        Err(Error::Unavailable(format!(
            "{OPERATION}: other sessions changed node {} or node {} at the same time",
            edge.from, edge.to
        )))
    }

    async fn node(&self, id: &NodeId) -> Result<Option<GraphNode>> {
        let row: Option<(String,)> = sqlx::query_as(READ_NODE)
            .bind(Agtype::parameters(&json!({ "id": id.0 }))?)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db_error("read the graph node", error))?;
        row.map(|(text,)| node_from_text(&text)).transpose()
    }

    async fn neighbors(
        &self,
        id: &NodeId,
        relation: Option<&str>,
        direction: Direction,
    ) -> Result<Vec<GraphNode>> {
        let label = relation.map(RelationLabel::parse).transpose()?;
        let rows: Vec<(String, Option<String>, i64)> =
            sqlx::query_as(AssertSqlSafe(neighbors_sql(label, direction)))
                .bind(Agtype::parameters(&json!({ "id": id.0 }))?)
                .fetch_all(&self.pool)
                .await
                .map_err(|error| db_error("read the graph neighbors", error))?;
        neighbors_from_rows(
            rows.into_iter()
                .map(|(node, created_at, edge)| NeighborRow {
                    node,
                    created_at,
                    edge,
                })
                .collect(),
        )
    }

    async fn nodes_by_kind(&self, kind: NodeKind, limit: usize) -> Result<Vec<GraphNode>> {
        let rows: Vec<(String,)> = sqlx::query_as(NODES_BY_KIND)
            .bind(Agtype::parameters(
                &json!({ "kind": variant_name(&kind)? }),
            )?)
            .bind(sql_limit(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(|error| db_error("read the graph nodes", error))?;
        rows.iter().map(|(text,)| node_from_text(text)).collect()
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn invalid_input(result: Result<RelationLabel<'_>>) -> String {
        match result {
            Err(Error::InvalidInput(message)) => message,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn the_contract_relation_names_are_valid_labels() {
        use aegis_contracts::graph::relation;
        let names = [
            relation::INVOLVES,
            relation::PART_OF,
            relation::ACTED_ON,
            relation::HAS_ROLE,
            relation::OWNS,
            relation::AUTHENTICATED_FROM,
            relation::MEMBER_OF,
            relation::CONTAINED_BY,
        ];
        for name in names {
            assert_eq!(RelationLabel::parse(name).unwrap().as_str(), name);
        }
        assert_eq!(RelationLabel::parse("a").unwrap().as_str(), "a");
        assert_eq!(RelationLabel::parse("seen_2x").unwrap().as_str(), "seen_2x");
        let longest = "r".repeat(MAX_RELATION_NAME_BYTES);
        assert_eq!(RelationLabel::parse(&longest).unwrap().as_str(), longest);
    }

    #[test]
    fn names_that_are_not_plain_identifiers_are_rejected() {
        let too_long = "r".repeat(MAX_RELATION_NAME_BYTES + 1);
        let names = [
            "",
            "Owns",
            "OWNS",
            "1owns",
            "_owns",
            "owns ",
            " owns",
            "has-role",
            "has role",
            "owns]->(b) DETACH DELETE b //",
            "owns`",
            "owns$cypher$",
            "owns;",
            "owns\n",
            "owns\0",
            "öwns",
            "owns:admin",
            "owns|has_role",
            "owns*1..5",
            too_long.as_str(),
        ];
        for name in names {
            let message = invalid_input(RelationLabel::parse(name));
            assert!(
                message.contains("^[a-z][a-z0-9_]*$"),
                "{name:?} -> {message}"
            );
        }
    }

    #[test]
    fn the_relation_name_is_the_edge_label_of_the_statement() {
        let label = RelationLabel::parse("has_role").unwrap();
        let upsert = upsert_edge_statement(label);
        assert_eq!(upsert.matches("has_role").count(), 1);
        assert!(upsert.contains("MERGE (a)-[r:has_role]->(b)"), "{upsert}");

        let read = read_edge_statement(label);
        assert_eq!(read.matches("has_role").count(), 1);
        assert!(read.contains("(a:Node)-[r:has_role]->(b:Node)"), "{read}");
    }

    #[test]
    fn the_lock_key_of_a_relation_is_different_for_each_start_name_and_end() {
        let key = |from: &str, relation: &str, to: &str| {
            let edge = GraphEdge::new(NodeId(from.to_owned()), relation, NodeId(to.to_owned()));
            edge_lock_key(&edge, RelationLabel::parse(relation).unwrap())
        };
        assert_eq!(key("user:a", "owns", "host:b"), "6:user:a>owns>host:b");
        assert_ne!(key("a", "owns", "b"), key("b", "owns", "a"));
        assert_ne!(key("a", "owns", "b"), key("a", "has_role", "b"));
        // A part of one identifier cannot pass for a part of the other identifier.
        assert_ne!(key("a>owns>b", "owns", "c"), key("a", "owns", "b>owns>c"));
    }

    #[test]
    fn neighbor_statements_follow_the_direction() {
        let label = RelationLabel::parse("owns").unwrap();

        let outgoing = neighbors_sql(Some(label), Direction::Outgoing);
        assert!(
            outgoing.contains("(n:Node)-[r:owns]->(m:Node)"),
            "{outgoing}"
        );
        assert!(!outgoing.contains("<-"), "{outgoing}");

        let incoming = neighbors_sql(Some(label), Direction::Incoming);
        assert!(
            incoming.contains("(n:Node)<-[r:owns]-(m:Node)"),
            "{incoming}"
        );
        assert!(!incoming.contains("->"), "{incoming}");

        let both = neighbors_sql(Some(label), Direction::Both);
        assert_eq!(both, format!("{outgoing} UNION ALL {incoming}"));

        let any_out = neighbors_sql(None, Direction::Outgoing);
        assert_eq!(any_out, NEIGHBORS_OUT);
        assert!(any_out.contains("(n:Node)-[r]->(m:Node)"), "{any_out}");
        let any_in = neighbors_sql(None, Direction::Incoming);
        assert_eq!(any_in, NEIGHBORS_IN);
        assert!(any_in.contains("(n:Node)<-[r]-(m:Node)"), "{any_in}");
    }

    #[test]
    fn each_statement_takes_its_values_from_the_parameter_map() {
        let label = RelationLabel::parse("owns").unwrap();
        let statements = [
            READ_NODE.to_owned(),
            UPDATE_NODE.to_owned(),
            CREATE_NODE.to_owned(),
            EXISTING_NODE_IDS.to_owned(),
            NODES_BY_KIND.to_owned(),
            upsert_edge_statement(label),
            read_edge_statement(label),
            neighbors_sql(Some(label), Direction::Both),
            neighbors_sql(None, Direction::Both),
        ];
        for statement in statements {
            // The parameter map is the third argument of each cypher() call.
            let calls = statement
                .matches("ag_catalog.cypher('aegis_graph', $cypher$")
                .count();
            assert!(calls >= 1, "{statement}");
            assert_eq!(
                statement.matches("$cypher$, $1)").count(),
                calls,
                "{statement}"
            );
            // No Cypher body has a quoted text value. The bodies are the odd parts.
            let bodies: Vec<&str> = statement.split("$cypher$").skip(1).step_by(2).collect();
            assert_eq!(bodies.len(), calls, "{statement}");
            for body in bodies {
                assert!(!body.contains('\'') && !body.contains('"'), "{statement}");
            }
        }
    }

    #[test]
    fn node_parameters_hold_all_fields_of_the_node() {
        let node = GraphNode {
            id: NodeId("user:alice".to_owned()),
            kind: NodeKind::Identity,
            label: "Alice".to_owned(),
            properties: BTreeMap::from([("tenant".to_owned(), json!("contoso"))]),
            updated_at: Utc.with_ymd_and_hms(2026, 3, 4, 5, 6, 7).unwrap(),
        };
        let parameters: Value =
            serde_json::from_str(node_parameters(&node).unwrap().as_str()).unwrap();
        assert_eq!(
            parameters,
            json!({
                "id": "user:alice",
                "kind": "identity",
                "label": "Alice",
                "updated_at": "2026-03-04T05:06:07.000000000Z",
                "props": { "tenant": "contoso" },
            })
        );
    }

    #[test]
    fn a_node_with_no_properties_sends_an_empty_map() {
        let node = GraphNode {
            id: NodeId("host:h1".to_owned()),
            kind: NodeKind::Asset,
            label: "h1".to_owned(),
            properties: BTreeMap::new(),
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        };
        let parameters: Value =
            serde_json::from_str(node_parameters(&node).unwrap().as_str()).unwrap();
        // A null value would remove the property from the vertex.
        assert_eq!(parameters["props"], json!({}));
    }

    #[test]
    fn a_node_identifier_above_the_limit_is_rejected() {
        let mut node = GraphNode {
            id: NodeId("x".repeat(MAX_NODE_ID_BYTES)),
            kind: NodeKind::Asset,
            label: String::new(),
            properties: BTreeMap::new(),
            updated_at: Utc::now(),
        };
        assert!(node_parameters(&node).is_ok());
        node.id.0.push('x');
        let error = node_parameters(&node).unwrap_err();
        assert!(matches!(error, Error::InvalidInput(message) if message.contains("1025 bytes")));
    }

    #[test]
    fn graph_times_have_a_fixed_width_and_sort_in_time_order() {
        let early = Utc.with_ymd_and_hms(2026, 11, 17, 21, 3, 2).unwrap();
        let later = early + chrono::Duration::nanoseconds(1);
        let much_later = early + chrono::Duration::milliseconds(500);
        let texts: Vec<String> = [early, later, much_later]
            .into_iter()
            .map(|time| graph_time(time).unwrap())
            .collect();
        assert_eq!(
            texts,
            [
                "2026-11-17T21:03:02.000000000Z",
                "2026-11-17T21:03:02.000000001Z",
                "2026-11-17T21:03:02.500000000Z",
            ]
        );
        let mut sorted = texts.clone();
        sorted.sort();
        assert_eq!(sorted, texts);
        // The text gives back the same instant, with nanoseconds.
        for (text, time) in texts.iter().zip([early, later, much_later]) {
            assert_eq!(text.parse::<DateTime<Utc>>().unwrap(), time);
        }
    }

    #[test]
    fn a_year_outside_four_digits_is_rejected() {
        let far = Utc.with_ymd_and_hms(10_000, 1, 1, 0, 0, 0).unwrap();
        let error = graph_time(far).unwrap_err();
        assert!(matches!(error, Error::InvalidInput(message) if message.contains("10000")));
    }

    #[test]
    fn a_stored_vertex_maps_to_a_node() {
        let text = r#"{"id": "sp:1", "kind": "identity", "label": "sp-1", "props": {"n": null, "f": 1e+19, "i": 7, "nested": {"a": [1.5, "x"]}}, "updated_at": "2026-11-17T21:03:04.000000001Z"}"#;
        let node = node_from_text(text).unwrap();
        assert_eq!(node.id, NodeId("sp:1".to_owned()));
        assert_eq!(node.kind, NodeKind::Identity);
        assert_eq!(node.label, "sp-1");
        assert_eq!(
            node.updated_at,
            Utc.with_ymd_and_hms(2026, 11, 17, 21, 3, 4).unwrap()
                + chrono::Duration::nanoseconds(1)
        );
        assert_eq!(
            Value::Object(node.properties.into_iter().collect()),
            json!({ "n": null, "f": 1e19, "i": 7, "nested": { "a": [1.5, "x"] } })
        );
    }

    #[test]
    fn a_vertex_without_the_node_fields_is_a_serialization_error() {
        let error = node_from_text(r#"{"id": "manual", "label": "x"}"#).unwrap_err();
        match error {
            Error::Serialization(message) => {
                assert!(
                    message.contains("a graph node cannot be decoded"),
                    "{message}"
                );
                assert!(message.contains("kind"), "{message}");
            }
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    fn row(id: &str, created_at: Option<&str>, edge: i64) -> NeighborRow {
        NeighborRow {
            node: format!(
                r#"{{"id": "{id}", "kind": "asset", "label": "{id}", "props": {{}}, "updated_at": "2026-01-01T00:00:00.000000000Z"}}"#
            ),
            created_at: created_at.map(|time| format!("\"{time}\"")),
            edge,
        }
    }

    fn ids(nodes: &[GraphNode]) -> Vec<&str> {
        nodes.iter().map(|node| node.id.0.as_str()).collect()
    }

    #[test]
    fn neighbors_are_in_the_order_of_the_first_write_of_their_relations() {
        let rows = vec![
            row("c", Some("2026-01-01T00:00:03.000000000Z"), 30),
            row("a", Some("2026-01-01T00:00:01.000000000Z"), 99),
            row("b", Some("2026-01-01T00:00:02.000000000Z"), 10),
        ];
        assert_eq!(ids(&neighbors_from_rows(rows).unwrap()), ["a", "b", "c"]);
    }

    #[test]
    fn a_node_with_two_relations_is_one_neighbor_at_its_first_position() {
        let rows = vec![
            row("b", Some("2026-01-01T00:00:02.000000000Z"), 2),
            row("a", Some("2026-01-01T00:00:03.000000000Z"), 3),
            row("a", Some("2026-01-01T00:00:01.000000000Z"), 1),
        ];
        assert_eq!(ids(&neighbors_from_rows(rows).unwrap()), ["a", "b"]);
    }

    #[test]
    fn relations_with_the_same_time_keep_the_order_of_their_edge_numbers() {
        let time = Some("2026-01-01T00:00:01.000000000Z");
        let rows = vec![row("b", time, 8), row("a", time, 9), row("c", None, 50)];
        // A relation that a different tool made has no time. It sorts first.
        assert_eq!(ids(&neighbors_from_rows(rows).unwrap()), ["c", "b", "a"]);
    }

    #[test]
    fn counts_and_identifiers_decode_from_agtype_text() {
        assert_eq!(count_from_text("42").unwrap(), 42);
        assert!(matches!(
            count_from_text("-1"),
            Err(Error::Serialization(_))
        ));
        assert_eq!(
            string_from_text("a graph node identifier", r#""user:a\"b""#).unwrap(),
            "user:a\"b"
        );
    }
}
