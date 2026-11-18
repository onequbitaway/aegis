//! A replay and a service run with PostgreSQL storage, the PostgreSQL audit log, and a
//! NATS bus.
//!
//! The test starts two containers on free ports of the local host: PostgreSQL from
//! `deploy/docker/postgres/Dockerfile`, and NATS with JetStream. Each name starts with
//! `aegis-int-`. The test removes the containers when it ends. A watchdog in each
//! container also stops it when the test process goes away early.
#![cfg(feature = "docker-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_app::actions::DispatchResult;
use aegis_app::{RunOptions, starter};
use aegis_contracts::action::{ActionDisposition, ActionStatus};
use aegis_contracts::audit::{AuditKind, AuditLog, AuditRecord};
use aegis_contracts::bus::subject;
use aegis_contracts::common::Severity;
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_core::Shutdown;
use aegis_ingest::RunOutcome;
use aegis_storage::{PgStore, StorageConfig};
use aegis_testkit::fixtures;
use futures::StreamExt;

use support::{Starter, replace_once};

const POSTGRES_IMAGE: &str = "aegis-int-postgres:test";
const NATS_IMAGE: &str = "nats:2.12-alpine";
const LABEL: &str = "aegis.test=int-app";
const START_LIMIT: Duration = Duration::from_secs(180);
const WAIT: Duration = Duration::from_secs(120);

/// The command of the watchdog. `cat` ends when the test process goes away. The command
/// then stops process 1 of the container.
const WATCHDOG: &str = "cat >/dev/null; while kill -s INT 1 2>/dev/null; do sleep 1; done";

fn docker(arguments: &[&str]) -> Output {
    Command::new("docker")
        .args(arguments)
        .output()
        .unwrap_or_else(|error| {
            panic!("aegis-app docker-tests: the docker command did not run: {error}")
        })
}

fn run_docker(arguments: &[&str]) -> String {
    let output = docker(arguments);
    assert!(
        output.status.success(),
        "aegis-app docker-tests: docker {arguments:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn unique(kind: &str) -> String {
    let nanoseconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("aegis-int-{kind}-{}-{nanoseconds:08x}", std::process::id())
}

/// A container that the test started. The container goes away with this value.
struct Container {
    name: String,
    watchdog: Option<Child>,
}

impl Container {
    fn watch(mut self) -> Self {
        let watchdog = Command::new("docker")
            .args(["exec", "--interactive", &self.name, "sh", "-c", WATCHDOG])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.watchdog = Some(watchdog);
        self
    }

    fn logs(&self) -> String {
        let output = docker(&["logs", "--tail", "40", &self.name]);
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let removed = docker(&["rm", "--force", "--volumes", &self.name]);
        if !removed.status.success() {
            eprintln!(
                "aegis-app docker-tests: could not remove the container {}: {}",
                self.name,
                String::from_utf8_lossy(&removed.stderr)
            );
        }
        if let Some(watchdog) = &mut self.watchdog {
            let _ = watchdog.wait();
        }
    }
}

/// Starts PostgreSQL with Apache AGE and pgvector. Returns the container and the URL.
async fn start_postgres() -> (Container, String) {
    let context = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/docker/postgres");
    run_docker(&[
        "build",
        "--quiet",
        "--tag",
        POSTGRES_IMAGE,
        context.to_str().unwrap(),
    ]);
    let name = unique("postgres");
    let password = format!("pw{:x}{:x}", std::process::id(), rand_token());
    run_docker(&[
        "run",
        "--detach",
        "--rm",
        "--name",
        &name,
        "--label",
        LABEL,
        "--env",
        &format!("POSTGRES_PASSWORD={password}"),
        // Docker selects a free port of this host.
        "--publish",
        "127.0.0.1::5432",
        POSTGRES_IMAGE,
        "postgres",
        "-c",
        "shared_preload_libraries=age",
        "-c",
        "fsync=off",
        "-c",
        "synchronous_commit=off",
        "-c",
        "full_page_writes=off",
    ]);
    let container = Container {
        name: name.clone(),
        watchdog: None,
    }
    .watch();
    let address = run_docker(&["port", &name, "5432/tcp"])
        .lines()
        .next()
        .unwrap()
        .trim()
        .to_owned();
    let url = format!("postgres://postgres:{password}@{address}/postgres?sslmode=disable");

    // The server refuses connections until its first start is complete.
    let started = Instant::now();
    loop {
        match PgStore::connect(&StorageConfig::new(url.clone())).await {
            Ok(store) => {
                if store.ping().await.is_ok() {
                    store.close().await;
                    break;
                }
                store.close().await;
            }
            Err(_) if started.elapsed() < START_LIMIT => {}
            Err(error) => panic!(
                "aegis-app docker-tests: PostgreSQL did not accept connections: {error}\n{}",
                container.logs()
            ),
        }
        assert!(
            started.elapsed() < START_LIMIT,
            "aegis-app docker-tests: PostgreSQL did not answer:\n{}",
            container.logs()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    (container, url)
}

fn rand_token() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
}

/// Returns `true` if a NATS server sends its greeting on this address.
fn greets(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(1)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .is_err()
    {
        return false;
    }
    let mut greeting = [0_u8; 4];
    stream.read_exact(&mut greeting).is_ok() && &greeting == b"INFO"
}

/// Starts NATS with JetStream. Returns the container and the URL.
async fn start_nats() -> (Container, String) {
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .unwrap()
        .port();
    let name = unique("nats");
    run_docker(&[
        "run",
        "--detach",
        "--rm",
        "--name",
        &name,
        "--label",
        LABEL,
        "--publish",
        &format!("127.0.0.1:{port}:4222"),
        // `timeout` ends the server after a fixed time, so a container that a killed test
        // process leaves behind does not stay for long.
        "--entrypoint",
        "timeout",
        NATS_IMAGE,
        "900",
        "nats-server",
        "--jetstream",
    ]);
    let container = Container {
        name,
        watchdog: None,
    };
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let started = Instant::now();
    while !greets(address) {
        assert!(
            started.elapsed() < START_LIMIT,
            "aegis-app docker-tests: NATS did not answer:\n{}",
            container.logs()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (container, format!("nats://127.0.0.1:{port}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replay_and_a_service_run_with_postgres_and_nats() {
    let version = docker(&["version", "--format", "{{.Server.Version}}"]);
    assert!(
        version.status.success(),
        "aegis-app docker-tests: Docker is not available. Start Docker, or run the tests \
         without the feature `docker-tests`.\n{}",
        String::from_utf8_lossy(&version.stderr)
    );
    let ((postgres, database_url), (nats, nats_url)) = tokio::join!(start_postgres(), start_nats());

    let starter = Starter::new();
    std::fs::write(starter.path().join("events.jsonl"), starter::attack_log()).unwrap();
    let config = starter.config_with(|text| {
        let text = replace_once(
            &text,
            "kind = \"memory\"\n\n[storage]",
            &format!(
                "kind = \"nats\"\n\n[bus.nats]\nurls = [\"{nats_url}\"]\n\n[bus.stream]\n\
                 name = \"AEGIS_INT\"\nstorage = \"memory\"\n\n[storage]"
            ),
        );
        let text = replace_once(
            &text,
            "kind = \"memory\"\n\n[audit]",
            &format!("kind = \"postgres\"\nurl = \"{database_url}\"\n\n[audit]"),
        );
        let text = replace_once(
            &text,
            "kind = \"file\"\npath = \"data/audit.jsonl\"",
            "kind = \"postgres\"",
        );
        text + "\n[[sources]]\ntype = \"file\"\nname = \"recorded\"\npath = \"events.jsonl\"\n"
    });
    let app = Arc::new(starter.build(&config, |builder| builder).await);
    assert_eq!(app.settings().storage.kind(), "postgres");
    assert_eq!(app.audit_path(), None);

    // --- The replay.
    let report = app.replay(fixtures::artex_style_attack()).await.unwrap();

    assert_eq!(report.detections.len(), 8);
    assert_eq!(report.incidents.len(), 1);
    let incident = &report.incidents[0];
    assert_eq!(incident.severity, Severity::Critical);
    assert_eq!(incident.status, IncidentStatus::Investigating);
    assert_eq!(incident.detections.len(), 8);
    assert_eq!(report.actions.len(), 23);
    for action in &report.actions {
        assert!(
            matches!(&action.result, DispatchResult::Disposition(ActionDisposition::Executed(outcome))
                if outcome.status == ActionStatus::Simulated),
            "{:?}",
            action.result
        );
    }
    assert!(!report.changed_the_environment());
    assert!(report.audit.verification.valid);
    assert_eq!(report.agents.unwrap().tasks_failed, 0);

    // A second connection reads the database: the incident and the audit log are there,
    // and the chain verifies from the table.
    let reader = PgStore::connect(&StorageConfig::new(database_url.clone()))
        .await
        .unwrap();
    let stored: Vec<Incident> = reader.incidents().list(None, 10).await.unwrap();
    assert_eq!(stored, std::slice::from_ref(incident));
    let verification = reader.audit().verify().await.unwrap();
    assert!(verification.valid, "{verification:?}");
    assert_eq!(verification.checked, report.audit.records);
    let records: Vec<AuditRecord> = reader.audit().read(1, 100_000).await.unwrap();
    let count = |kind: AuditKind| records.iter().filter(|record| record.kind == kind).count();
    assert_eq!(count(AuditKind::Detection), 8);
    assert_eq!(count(AuditKind::ActionProposed), 23);
    assert_eq!(count(AuditKind::ActionExecuted), 23);
    // The Defensive Graph is in the database too.
    let nodes = reader.graph().node_count().await.unwrap();
    assert!(nodes >= 8, "{nodes}");

    // The NATS stream has each state of the incident and each audit record.
    let bus = app.bus();
    let mut incidents = bus
        .subscribe(subject::INCIDENTS, Some("int-test-incidents"))
        .await
        .unwrap();
    let mut states = Vec::new();
    for _ in 0..7 {
        let message = tokio::time::timeout(WAIT, incidents.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        states.push(message.decode::<Incident>().unwrap());
    }
    assert_eq!(states[0].status, IncidentStatus::Open);
    assert_eq!(states[6].detections.len(), 8);
    assert_eq!(states[6].status, IncidentStatus::Investigating);
    drop(incidents);
    let mut audit = bus
        .subscribe(subject::AUDIT, Some("int-test-audit"))
        .await
        .unwrap();
    let mut published = Vec::new();
    for _ in 0..records.len() {
        let message = tokio::time::timeout(WAIT, audit.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        published.push(message.decode::<AuditRecord>().unwrap());
    }
    assert_eq!(published, records);
    drop(audit);
    assert_eq!(app.audit().publish_failures(), 0);

    // --- The service on the same bus and database. Each subscriber has a durable name
    // of its own: the detection runner, and the two subscriptions of the agent runtime.
    // The NATS bus rejects a second pattern under one durable name, so a successful run
    // shows that the names are different.
    let options = RunOptions {
        stop_when_sources_end: true,
        services: Vec::new(),
    };
    let summary = tokio::time::timeout(WAIT, app.run_with(Shutdown::new(), options))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(summary.sources.len(), 1);
    assert_eq!(summary.sources[0].outcome, RunOutcome::Completed);
    assert_eq!(
        summary.sources[0].stats.events_published,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    // The detection runner read each event from NATS. The engine knows the detections
    // from the replay, so the incident does not change.
    assert_eq!(
        summary.progress.events_processed,
        fixtures::ATTACK_LOG_EVENTS as u64
    );
    assert_eq!(summary.progress.detections, 8);
    assert_eq!(reader.incidents().list(None, 10).await.unwrap().len(), 1);
    assert!(reader.audit().verify().await.unwrap().valid);

    reader.close().await;
    app.close().await;
    drop(app);
    drop(postgres);
    drop(nats);
}
