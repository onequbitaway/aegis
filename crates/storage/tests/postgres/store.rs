//! Tests of the connection, the migrations, and the error mapping.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use aegis_contracts::action::{ActionKind, ActionRequest};
use aegis_contracts::audit::{AuditEntry, AuditKind};
use aegis_contracts::common::{ApprovalId, EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::graph::{Direction, GraphEdge, GraphNode, NodeId, VectorRecord, relation};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::policy::{
    ActionTier, ApprovalRequest, ApprovalStatus, PolicyDecision, PolicyEffect, Principal,
    PrincipalKind,
};
use aegis_contracts::{ApprovalQueue, AuditLog, DefensiveGraph, Error, IncidentStore, VectorStore};
use aegis_storage::PgStore;
use chrono::Utc;
use sqlx::{Connection, Executor};
use uuid::Uuid;

use crate::support::{TestDb, config};

fn incident(title: &str) -> Incident {
    Incident {
        id: IncidentId::new(),
        title: title.to_owned(),
        summary: String::new(),
        severity: Severity::Medium,
        status: IncidentStatus::Open,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        tenant: None,
        detections: Vec::new(),
        entities: Vec::new(),
        attack: Vec::new(),
        timeline: Vec::new(),
    }
}

async fn applied_migrations(database: &TestDb) -> Vec<i64> {
    let mut sql = database.sql().await;
    let versions =
        sqlx::query_scalar("SELECT version FROM aegis.storage_migrations ORDER BY version")
            .fetch_all(&mut sql)
            .await
            .unwrap();
    sql.close().await.unwrap();
    versions
}

#[tokio::test]
async fn migrations_run_twice_without_error_and_keep_the_data() {
    let database = TestDb::without_schema().await;
    database.store.migrate().await.unwrap();
    let first_run = applied_migrations(&database).await;
    assert!(!first_run.is_empty());

    let node = GraphNode::from_entity(&EntityRef::new(EntityKind::Host, "host-1"));
    database
        .store
        .graph()
        .upsert_node(node.clone())
        .await
        .unwrap();
    let record = database
        .store
        .audit()
        .append(AuditEntry::new(
            AuditKind::ConfigChange,
            "operator",
            "Changed the policy.",
        ))
        .await
        .unwrap();
    let saved = incident("Kept");
    database.store.incidents().save(&saved).await.unwrap();

    database.store.migrate().await.unwrap();
    // A second process runs the migrations when it starts.
    let second = database.second_store().await;
    second.migrate().await.unwrap();

    assert_eq!(applied_migrations(&database).await, first_run);
    assert_eq!(second.graph().node_count().await.unwrap(), 1);
    let read = second.graph().node(&node.id).await.unwrap().unwrap();
    assert_eq!(read.label, "host-1");
    assert_eq!(second.audit().read(1, 10).await.unwrap(), vec![record]);
    assert_eq!(second.incidents().get(saved.id).await.unwrap(), Some(saved));
}

#[tokio::test]
async fn several_processes_can_run_the_migrations_at_the_same_time() {
    let database = TestDb::without_schema().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let store = database.second_store().await;
        tasks.spawn(async move { store.migrate().await });
    }
    let results = tokio::time::timeout(Duration::from_secs(120), tasks.join_all())
        .await
        .unwrap();
    assert_eq!(results.len(), 4);
    for result in results {
        result.unwrap();
    }
    assert_eq!(database.store.graph().node_count().await.unwrap(), 0);
    assert!(database.store.audit().verify().await.unwrap().valid);
}

#[tokio::test]
async fn a_database_without_the_schema_gives_a_configuration_error() {
    let database = TestDb::without_schema().await;

    let error = database
        .store
        .incidents()
        .get(IncidentId::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("Run the migrations")),
        "{error:?}"
    );

    let error = database
        .store
        .graph()
        .node(&NodeId("host:h1".to_owned()))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("Run the migrations")),
        "{error:?}"
    );
    assert!(!error.is_retryable());
}

#[tokio::test]
async fn a_rejected_login_is_unauthorized_and_the_error_hides_the_url() {
    let database = TestDb::new().await;
    let url = database.url_for_role("postgres", "wrong-hunter2-password");
    let error = PgStore::connect(&config(&url)).await.unwrap_err();
    match &error {
        Error::Unauthorized(message) => assert_eq!(
            message,
            "connect to the database: the database rejected the credentials (SQLSTATE 28P01)"
        ),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    assert!(!error.is_retryable());
}

#[tokio::test]
async fn the_debug_output_of_the_store_does_not_show_the_url() {
    let mut database = TestDb::new().await;
    // A role and a password that no other text contains.
    let password = format!("secret-{}", Uuid::now_v7().simple());
    let role = database.create_superuser(&password).await;
    let url = url::Url::parse(&database.url_for_role(&role, &password)).unwrap();
    let address = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
    let database_name = url.path().trim_start_matches('/').to_owned();
    assert!(database_name.starts_with("aegis_test_"), "{database_name}");
    // The URL has each text that the outputs must not have.
    for secret in [&password, &role, &address, &database_name] {
        assert!(url.as_str().contains(secret.as_str()), "{secret}");
    }

    let store = PgStore::connect(&config(url.as_str())).await.unwrap();
    store.ping().await.unwrap();
    let outputs = [
        format!("{store:?}"),
        format!("{:?}", store.graph()),
        format!("{:?}", store.vectors()),
        format!("{:?}", store.incidents()),
        format!("{:?}", store.audit()),
        format!("{:?}", store.approvals()),
        format!("{:?}", config(url.as_str())),
    ];
    for output in outputs {
        assert!(!output.is_empty());
        assert!(!output.contains(&password), "{output}");
        assert!(!output.contains(&role), "{output}");
        assert!(!output.contains(&address), "{output}");
        assert!(!output.contains(&database_name), "{output}");
    }
    store.close().await;
}

#[tokio::test]
async fn a_certificate_file_that_does_not_exist_gives_a_clear_error() {
    let database = TestDb::new().await;
    let url = database.url(&[
        ("sslmode", "verify-full"),
        ("sslrootcert", "/aegis-test/absent/authority.pem"),
    ]);
    let error = PgStore::connect(&config(&url)).await.unwrap_err();
    match &error {
        Error::Unavailable(message) => assert_eq!(
            message,
            "connect to the database: the database connection failed. \
             A socket or a certificate file that the database URL names does not exist"
        ),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn a_database_that_does_not_exist_is_a_configuration_error() {
    let database = TestDb::new().await;
    let mut url = url::Url::parse(&database.url(&[])).unwrap();
    url.set_path("/aegis_test_absent_database");
    let error = PgStore::connect(&config(url.as_str())).await.unwrap_err();
    match &error {
        Error::Config(message) => assert_eq!(
            message,
            "connect to the database: the database in the URL does not exist (SQLSTATE 3D000)"
        ),
        other => panic!("expected Config, got {other:?}"),
    }
}

#[tokio::test]
async fn a_closed_store_is_unavailable() {
    let database = TestDb::new().await;
    let store = database.second_store().await;
    store.ping().await.unwrap();
    store.close().await;
    let error = store.ping().await.unwrap_err();
    match &error {
        Error::Unavailable(message) => {
            assert_eq!(message, "check the database: the store is closed");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    assert!(error.is_retryable());
}

#[tokio::test]
async fn a_statement_that_waits_longer_than_the_limit_is_a_timeout() {
    let database = TestDb::new().await;
    let mut settings = config(&database.url(&[]));
    settings.statement_timeout_seconds = 1;
    let store = PgStore::connect(&settings).await.unwrap();

    let mut blocker = database.sql().await;
    blocker.execute("BEGIN").await.unwrap();
    blocker
        .execute("LOCK TABLE aegis.incidents IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();

    let id = IncidentId::new();
    let blocked = tokio::time::timeout(Duration::from_secs(30), store.incidents().get(id))
        .await
        .unwrap();
    let error = blocked.unwrap_err();
    assert!(matches!(&error, Error::Timeout(_)), "{error:?}");
    assert!(error.is_retryable());

    blocker.execute("ROLLBACK").await.unwrap();
    blocker.close().await.unwrap();
    // The same store works again when the lock is gone.
    assert_eq!(store.incidents().get(id).await.unwrap(), None);
}

#[tokio::test]
async fn a_value_that_the_database_cannot_hold_is_invalid_input() {
    let database = TestDb::new().await;
    let mut bad = incident("NUL in a column");
    bad.tenant = Some("contoso\0admin".to_owned());
    let error = database.store.incidents().save(&bad).await.unwrap_err();
    assert!(
        matches!(&error, Error::InvalidInput(message) if message.contains("SQLSTATE 22021")),
        "{error:?}"
    );
    assert_eq!(database.store.incidents().get(bad.id).await.unwrap(), None);
}

/// A file in the temporary directory. The file goes away with the value.
struct TemporaryFile(std::path::PathBuf);

impl TemporaryFile {
    fn with_contents(contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!("aegis-test-{}.pem", Uuid::now_v7().simple()));
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0) {
            eprintln!("could not remove {}: {error}", self.0.display());
        }
    }
}

async fn connection_is_encrypted(database: &TestDb, application: &str) -> Vec<bool> {
    let mut sql = database.sql().await;
    let encrypted = sqlx::query_scalar(
        "SELECT s.ssl FROM pg_catalog.pg_stat_ssl AS s \
         JOIN pg_catalog.pg_stat_activity AS a ON a.pid = s.pid \
         WHERE a.application_name = $1",
    )
    .bind(application)
    .fetch_all(&mut sql)
    .await
    .unwrap();
    sql.close().await.unwrap();
    encrypted
}

#[tokio::test]
async fn the_url_selects_tls_and_the_store_checks_the_server_certificate() {
    let database = TestDb::new().await;
    let mut sql = database.sql().await;
    let server_tls: String = sqlx::query_scalar("SHOW ssl")
        .fetch_one(&mut sql)
        .await
        .unwrap();

    if server_tls != "on" {
        // The server has no TLS. A URL that asks for TLS must not get a plain connection.
        sql.close().await.unwrap();
        let url = database.url(&[("sslmode", "require")]);
        let error = PgStore::connect(&config(&url)).await.unwrap_err();
        assert!(matches!(&error, Error::Unavailable(_)), "{error:?}");
        return;
    }

    // sslmode=require: the connection has TLS.
    let application = format!("aegis-tls-{}", Uuid::now_v7().simple());
    let url = database.url(&[("sslmode", "require"), ("application_name", &application)]);
    let store = PgStore::connect(&config(&url)).await.unwrap();
    store.ping().await.unwrap();
    assert_eq!(
        connection_is_encrypted(&database, &application).await,
        [true]
    );
    store.close().await;

    // sslmode=disable: the connection has no TLS.
    let application = format!("aegis-plain-{}", Uuid::now_v7().simple());
    let url = database.url(&[("sslmode", "disable"), ("application_name", &application)]);
    let store = PgStore::connect(&config(&url)).await.unwrap();
    store.ping().await.unwrap();
    assert_eq!(
        connection_is_encrypted(&database, &application).await,
        [false]
    );
    store.close().await;

    // sslmode=verify-full: a certificate from an unknown authority is rejected.
    let url = database.url(&[("sslmode", "verify-full")]);
    let error = PgStore::connect(&config(&url)).await.unwrap_err();
    match &error {
        Error::Unavailable(message) => assert_eq!(
            message,
            "connect to the database: the TLS connection to the database failed. \
             Check sslmode and sslrootcert in the database URL"
        ),
        other => panic!("expected Unavailable, got {other:?}"),
    }

    // sslmode=verify-ca with the certificate of the server as the authority: accepted.
    let certificate: String = sqlx::query_scalar(
        "SELECT pg_catalog.pg_read_file(pg_catalog.current_setting('ssl_cert_file'))",
    )
    .fetch_one(&mut sql)
    .await
    .unwrap();
    sql.close().await.unwrap();
    let authority = TemporaryFile::with_contents(&certificate);
    let application = format!("aegis-verified-{}", Uuid::now_v7().simple());
    let url = database.url(&[
        ("sslmode", "verify-ca"),
        ("sslrootcert", authority.path()),
        ("application_name", &application),
    ]);
    let store = PgStore::connect(&config(&url)).await.unwrap();
    store.ping().await.unwrap();
    assert_eq!(
        connection_is_encrypted(&database, &application).await,
        [true]
    );
    store.close().await;

    // sslmode=verify-full with that authority: the certificate does not name this host.
    let url = database.url(&[
        ("sslmode", "verify-full"),
        ("sslrootcert", authority.path()),
    ]);
    let error = PgStore::connect(&config(&url)).await.unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.contains("the TLS connection")),
        "{error:?}"
    );
}

/// The privileges of an application role that does not own the schema.
///
/// The README of the crate gives the same statements to the operator.
const APPLICATION_ROLE_GRANTS: &[&str] = &[
    "GRANT USAGE ON SCHEMA aegis, aegis_graph, ag_catalog TO %I",
    "GRANT SELECT, INSERT ON aegis.audit_log TO %I",
    "GRANT SELECT, INSERT, UPDATE ON aegis.incidents, aegis.approvals, aegis.vectors TO %I",
    "GRANT SELECT, INSERT ON aegis.vector_collections TO %I",
    "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA aegis_graph TO %I",
    "GRANT USAGE ON ALL SEQUENCES IN SCHEMA aegis_graph TO %I",
    // The privileges on the tables of relation names that the owner makes later.
    "ALTER DEFAULT PRIVILEGES IN SCHEMA aegis_graph GRANT SELECT, INSERT, UPDATE ON TABLES TO %I",
    "ALTER DEFAULT PRIVILEGES IN SCHEMA aegis_graph GRANT USAGE ON SEQUENCES TO %I",
];

#[tokio::test]
async fn an_application_role_with_the_documented_privileges_can_use_each_repository() {
    let mut database = TestDb::new().await;
    let password = "application-role-password";
    let role = database.create_role(password).await;
    database
        .run_for_identifier(APPLICATION_ROLE_GRANTS, &role)
        .await;
    let store = PgStore::connect(&config(&database.url_for_role(&role, password)))
        .await
        .unwrap();
    store.ping().await.unwrap();

    // The Defensive Graph, with the relation names of the contracts.
    let graph = store.graph();
    let user = GraphNode::from_entity(&EntityRef::new(EntityKind::User, "user-1"));
    let host = GraphNode::from_entity(&EntityRef::new(EntityKind::Host, "host-1"));
    for node in [&user, &host] {
        graph.upsert_node(node.clone()).await.unwrap();
        graph.upsert_node(node.clone()).await.unwrap();
    }
    let edge = GraphEdge::new(user.id.clone(), relation::ACTED_ON, host.id.clone());
    graph.upsert_edge(edge.clone()).await.unwrap();
    graph.upsert_edge(edge).await.unwrap();
    assert_eq!(graph.node_count().await.unwrap(), 2);
    assert_eq!(graph.edge_count().await.unwrap(), 1);
    assert_eq!(
        graph
            .neighbors(&user.id, Some(relation::ACTED_ON), Direction::Outgoing)
            .await
            .unwrap(),
        vec![host.clone()]
    );
    assert_eq!(graph.node(&user.id).await.unwrap(), Some(user.clone()));

    // The vector store.
    let vectors = store.vectors();
    let record = VectorRecord {
        id: "note".to_owned(),
        embedding: vec![0.6, 0.8],
        text: "A note.".to_owned(),
        metadata: serde_json::Value::Null,
    };
    vectors.upsert("notes", record.clone()).await.unwrap();
    vectors.upsert("notes", record.clone()).await.unwrap();
    let found = vectors.search("notes", &[0.6, 0.8], 5).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].record, record);

    // The incident store.
    let incidents = store.incidents();
    let mut saved = incident("Role test");
    incidents.save(&saved).await.unwrap();
    saved.status = IncidentStatus::Contained;
    incidents.save(&saved).await.unwrap();
    assert_eq!(incidents.list(None, 5).await.unwrap(), vec![saved]);

    // The audit log.
    let audit = store.audit();
    let appended = audit
        .append(AuditEntry::new(
            AuditKind::Incident,
            "correlator",
            "Made an incident.",
        ))
        .await
        .unwrap();
    assert_eq!(audit.read(1, 5).await.unwrap(), vec![appended]);
    assert!(audit.verify().await.unwrap().valid);

    // The approval queue.
    let approvals = store.approvals();
    let request = ApprovalRequest {
        id: ApprovalId::new(),
        action: ActionRequest::new(
            ActionKind::IsolateHost,
            EntityRef::new(EntityKind::Host, "host-1"),
            "responder",
            "Test.",
        ),
        requested_by: Principal::new("responder", PrincipalKind::Agent, &["agent"]),
        decision: PolicyDecision {
            effect: PolicyEffect::RequireApproval,
            tier: ActionTier::Gated,
            reasons: Vec::new(),
            policy: None,
            evaluated_at: Utc::now(),
        },
        status: ApprovalStatus::Pending,
        requested_at: Utc::now(),
        decided_by: None,
        decided_at: None,
        note: None,
    };
    approvals.submit(request.clone()).await.unwrap();
    assert_eq!(approvals.pending().await.unwrap(), vec![request.clone()]);
    let approver = Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]);
    let decided = approvals
        .decide(request.id, true, &approver, None)
        .await
        .unwrap();
    assert_eq!(decided.status, ApprovalStatus::Approved);

    // The role cannot change the schema: the migrations and a new relation name fail.
    let error = store.migrate().await.unwrap_err();
    assert!(matches!(&error, Error::Unauthorized(_)), "{error:?}");
    let error = graph
        .upsert_edge(GraphEdge::new(
            user.id.clone(),
            "reported_by",
            host.id.clone(),
        ))
        .await
        .unwrap_err();
    assert!(matches!(&error, Error::Unauthorized(_)), "{error:?}");
    assert_eq!(graph.edge_count().await.unwrap(), 1);

    // The owner of the schema makes the relation name. Then the role can write it.
    let mut owner = database.sql().await;
    sqlx::query("SELECT aegis.ensure_relation($1)")
        .bind("reported_by")
        .execute(&mut owner)
        .await
        .unwrap();
    owner.close().await.unwrap();
    graph
        .upsert_edge(GraphEdge::new(
            user.id.clone(),
            "reported_by",
            host.id.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(graph.edge_count().await.unwrap(), 2);
    assert_eq!(
        graph
            .neighbors(&host.id, Some("reported_by"), Direction::Incoming)
            .await
            .unwrap(),
        vec![user]
    );
}

#[tokio::test]
async fn each_role_can_use_the_schema_when_the_owner_has_a_schema_with_its_own_name() {
    let mut database = TestDb::without_schema().await;
    let password = "owner-role-password";
    let owner = database.create_superuser(password).await;
    // PostgreSQL puts new objects in the schema with the name of the role, if it exists.
    database
        .run_for_identifier(&["CREATE SCHEMA %1$I AUTHORIZATION %1$I"], &owner)
        .await;
    let owner_store = PgStore::connect(&config(&database.url_for_role(&owner, password)))
        .await
        .unwrap();
    owner_store.migrate().await.unwrap();

    let record = VectorRecord {
        id: "note".to_owned(),
        embedding: vec![0.6, 0.8],
        text: "A note.".to_owned(),
        metadata: serde_json::Value::Null,
    };
    let node = GraphNode::from_entity(&EntityRef::new(EntityKind::Host, "host-1"));
    // The owner and a different role use the same objects.
    for store in [&owner_store, &database.store] {
        store
            .vectors()
            .upsert("notes", record.clone())
            .await
            .unwrap();
        let found = store
            .vectors()
            .search("notes", &[0.6, 0.8], 5)
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].record, record);
        store.graph().upsert_node(node.clone()).await.unwrap();
        assert_eq!(
            store.graph().node(&node.id).await.unwrap(),
            Some(node.clone())
        );
        store.migrate().await.unwrap();
    }
    owner_store.close().await;
}
