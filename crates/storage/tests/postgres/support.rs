//! A disposable PostgreSQL server and one database for each test.
//!
//! The server is one of these:
//!
//! - The server in the environment variable `AEGIS_TEST_DATABASE_URL`. The role in the URL
//!   must be a superuser, and the server must have the `age` and `vector` extensions.
//! - A Docker container from `deploy/docker/postgres/Dockerfile`. The first test builds the
//!   image and starts the container. The container goes away when the last test that uses
//!   it completes. A watchdog in the container also stops it when this test process goes
//!   away before that, for example after a kill signal.
//!
//! If the variable is not set and Docker is not available, each test fails.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Weak};
use std::time::Duration;

use aegis_storage::{PgStore, StorageConfig};
use sqlx::postgres::PgConnection;
use sqlx::{AssertSqlSafe, Connection, Executor};
use tokio::sync::Mutex;
use uuid::Uuid;

/// The environment variable that names a server to use in place of a container.
pub const DATABASE_URL_VARIABLE: &str = "AEGIS_TEST_DATABASE_URL";

/// The name of the image that the tests build.
const IMAGE: &str = "aegis-test-postgres:test";

/// The start of the name of each container that the tests start.
const CONTAINER_PREFIX: &str = "aegis-test-storage";

/// The label of each container that the tests start.
const CONTAINER_LABEL: &str = "aegis.test=storage";

/// The time to wait for a new server to accept connections.
const START_TIMEOUT: Duration = Duration::from_secs(120);

/// The time between two connection attempts to a new server.
const START_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The command of the watchdog. It runs in the container.
///
/// `cat` ends when the input closes. The input closes when this test process goes away.
/// The command then tells the server, which is process 1, to stop. The container goes
/// away with its server.
const WATCHDOG: &str = "cat >/dev/null; while kill -s INT 1 2>/dev/null; do sleep 1; done";

/// The server that the tests of this process share.
static SERVER: Mutex<Weak<Server>> = Mutex::const_new(Weak::new());

/// A PostgreSQL server for the tests.
pub struct Server {
    /// The URL of a superuser.
    admin_url: String,
    /// The container, if the tests started one.
    container: Option<Container>,
}

/// A container that the tests started.
struct Container {
    name: String,
    /// The watchdog process. Its input stays open while this value lives.
    watchdog: Child,
}

impl Server {
    /// Returns the shared server. Starts it if no test uses it at this time.
    async fn shared() -> Arc<Self> {
        let mut slot = SERVER.lock().await;
        if let Some(server) = slot.upgrade() {
            return server;
        }
        let server = Arc::new(match std::env::var(DATABASE_URL_VARIABLE) {
            Ok(url) if !url.trim().is_empty() => Self {
                admin_url: url,
                container: None,
            },
            _ => Self::start_container().await,
        });
        *slot = Arc::downgrade(&server);
        server
    }

    async fn start_container() -> Self {
        let version = docker(&["version", "--format", "{{.Server.Version}}"]);
        assert!(
            version.status.success(),
            "aegis-storage docker-tests: Docker is not available and {DATABASE_URL_VARIABLE} \
             is not set. Start Docker, or set {DATABASE_URL_VARIABLE} to the URL of a \
             PostgreSQL server that has the age and vector extensions.\n{}",
            String::from_utf8_lossy(&version.stderr)
        );

        let context = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/docker/postgres");
        let context = context.to_str().expect("the path of the image is UTF-8");
        let build = docker(&["build", "--quiet", "--tag", IMAGE, context]);
        assert!(
            build.status.success(),
            "aegis-storage docker-tests: the database image did not build:\n{}",
            String::from_utf8_lossy(&build.stderr)
        );

        let name = format!("{CONTAINER_PREFIX}-{}-{}", std::process::id(), short_id());
        let password = Uuid::now_v7().simple().to_string();
        let run = docker(&[
            "run",
            "--detach",
            "--rm",
            "--name",
            &name,
            "--label",
            CONTAINER_LABEL,
            "--env",
            &format!("POSTGRES_PASSWORD={password}"),
            // Docker selects a free port of this host.
            "--publish",
            "127.0.0.1::5432",
            IMAGE,
            "postgres",
            "-c",
            "shared_preload_libraries=age",
            "-c",
            "max_connections=400",
            // The data of a test server does not have to survive a crash.
            "-c",
            "fsync=off",
            "-c",
            "synchronous_commit=off",
            "-c",
            "full_page_writes=off",
            // The image has a self-signed certificate. The TLS tests use it.
            "-c",
            "ssl=on",
            "-c",
            "ssl_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem",
            "-c",
            "ssl_key_file=/etc/ssl/private/ssl-cert-snakeoil.key",
        ]);
        assert!(
            run.status.success(),
            "aegis-storage docker-tests: the database container did not start:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
        let watchdog = Command::new("docker")
            .args(["exec", "--interactive", &name, "sh", "-c", WATCHDOG])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let watchdog = match watchdog {
            Ok(watchdog) => watchdog,
            Err(error) => {
                docker(&["rm", "--force", "--volumes", &name]);
                panic!("aegis-storage docker-tests: the watchdog did not start: {error}");
            }
        };
        // From here on, the value removes the container when it goes away.
        let mut server = Self {
            admin_url: String::new(),
            container: Some(Container {
                name: name.clone(),
                watchdog,
            }),
        };

        let port = docker(&["port", &name, "5432/tcp"]);
        assert!(
            port.status.success(),
            "aegis-storage docker-tests: the container has no published port:\n{}",
            String::from_utf8_lossy(&port.stderr)
        );
        let address = String::from_utf8_lossy(&port.stdout)
            .lines()
            .next()
            .expect("docker port prints one address")
            .trim()
            .to_owned();
        server.admin_url = format!("postgres://postgres:{password}@{address}/postgres");

        let ready = tokio::time::timeout(START_TIMEOUT, async {
            loop {
                // The server refuses connections until its first start is complete.
                match PgConnection::connect(&server.admin_url).await {
                    Ok(connection) => break connection.close().await,
                    Err(_) => tokio::time::sleep(START_POLL_INTERVAL).await,
                }
            }
        })
        .await;
        match ready {
            Ok(Ok(())) => server,
            other => {
                let logs = docker(&["logs", "--tail", "40", &name]);
                panic!(
                    "aegis-storage docker-tests: the database did not accept connections \
                     ({other:?}):\n{}",
                    String::from_utf8_lossy(&logs.stderr)
                );
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let Some(container) = &mut self.container else {
            return;
        };
        let name = &container.name;
        let removed = docker(&["rm", "--force", "--volumes", name]);
        if !removed.status.success() {
            eprintln!(
                "aegis-storage docker-tests: could not remove container {name}: {}",
                String::from_utf8_lossy(&removed.stderr)
            );
        }
        // The watchdog ends with its container. Collect its exit status.
        if let Err(error) = container.watchdog.wait() {
            eprintln!("aegis-storage docker-tests: the watchdog of {name} did not end: {error}");
        }
    }
}

/// Runs one `docker` command and collects its output.
fn docker(arguments: &[&str]) -> Output {
    Command::new("docker")
        .args(arguments)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "aegis-storage docker-tests: the docker command did not run ({error}) and \
                 {DATABASE_URL_VARIABLE} is not set. Install Docker, or set \
                 {DATABASE_URL_VARIABLE} to the URL of a PostgreSQL server that has the age \
                 and vector extensions."
            )
        })
}

fn short_id() -> String {
    let id = Uuid::now_v7().simple().to_string();
    id[id.len() - 12..].to_owned()
}

/// Returns `url` with a different database, and optionally a different role.
fn url_with(url: &str, database: &str, role: Option<(&str, &str)>) -> String {
    let mut url = url::Url::parse(url).expect("the test database URL is a URL");
    url.set_path(&format!("/{database}"));
    if let Some((name, password)) = role {
        url.set_username(name).expect("the URL can have a user");
        url.set_password(Some(password))
            .expect("the URL can have a password");
    }
    url.into()
}

/// Makes a statement that cannot take bound parameters, for example `CREATE DATABASE`.
///
/// The server puts each value in the template with `format()`, which quotes an identifier
/// for `%I` and a literal for `%L`. The values go to the server as bound parameters.
async fn formatted(connection: &mut PgConnection, template: &str, values: &[&str]) -> String {
    let mut query = sqlx::query_scalar(match values.len() {
        1 => "SELECT pg_catalog.format($1, $2)",
        2 => "SELECT pg_catalog.format($1, $2, $3)",
        count => panic!("a template takes one or two values, not {count}"),
    })
    .bind(template);
    for value in values {
        query = query.bind(*value);
    }
    query.fetch_one(connection).await.unwrap()
}

/// One empty database for one test.
///
/// The database and its roles go away when the value goes away.
pub struct TestDb {
    /// A store that is connected to the database.
    pub store: PgStore,
    name: String,
    url: String,
    roles: Vec<String>,
    server: Arc<Server>,
}

impl TestDb {
    /// Makes a database and runs the migrations.
    pub async fn new() -> Self {
        let database = Self::without_schema().await;
        database.store.migrate().await.unwrap();
        database
    }

    /// Makes a database and does not run the migrations.
    pub async fn without_schema() -> Self {
        let server = Server::shared().await;
        let name = format!("aegis_test_{}", Uuid::now_v7().simple());
        let mut admin = PgConnection::connect(&server.admin_url).await.unwrap();
        let statement = formatted(&mut admin, "CREATE DATABASE %I", &[&name]).await;
        admin.execute(AssertSqlSafe(statement)).await.unwrap();
        admin.close().await.unwrap();

        let url = url_with(&server.admin_url, &name, None);
        let store = PgStore::connect(&config(&url)).await.unwrap();
        Self {
            store,
            name,
            url,
            roles: Vec::new(),
            server,
        }
    }

    /// Returns the URL of the database for the superuser, with more URL parameters.
    pub fn url(&self, parameters: &[(&str, &str)]) -> String {
        let mut url = url::Url::parse(&self.url).unwrap();
        for (key, value) in parameters {
            url.query_pairs_mut().append_pair(key, value);
        }
        url.into()
    }

    /// Returns the URL of the database for a different role.
    pub fn url_for_role(&self, name: &str, password: &str) -> String {
        url_with(&self.url, &self.name, Some((name, password)))
    }

    /// Opens a second store on the same database. It has its own connection pool, as a
    /// second process has.
    pub async fn second_store(&self) -> PgStore {
        PgStore::connect(&config(&self.url)).await.unwrap()
    }

    /// Opens a plain connection for SQL that goes around the store.
    pub async fn sql(&self) -> PgConnection {
        PgConnection::connect(&self.url).await.unwrap()
    }

    /// Runs statements that take one identifier, for example a `GRANT` for a role.
    ///
    /// Each template has one `%I` for the identifier.
    pub async fn run_for_identifier(&self, templates: &[&str], identifier: &str) {
        let mut connection = self.sql().await;
        for template in templates {
            let statement = formatted(&mut connection, template, &[identifier]).await;
            connection
                .execute(AssertSqlSafe(statement))
                .await
                .unwrap_or_else(|error| panic!("{template}: {error}"));
        }
        connection.close().await.unwrap();
    }

    /// Waits until `sessions` sessions of this database wait for a lock of a different
    /// session.
    pub async fn wait_for_blocked_sessions(&self, sessions: i64) {
        let mut connection = self.sql().await;
        let blocked = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity \
                     WHERE datname = pg_catalog.current_database() AND wait_event_type = 'Lock'",
                )
                .fetch_one(&mut connection)
                .await
                .unwrap();
                if waiting >= sessions {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        connection.close().await.unwrap();
        blocked.expect("the sessions did not wait for a lock in 60 seconds");
    }

    /// Makes a role that can log in and is not a superuser. Returns its name.
    pub async fn create_role(&mut self, password: &str) -> String {
        self.create_role_from("CREATE ROLE %I LOGIN PASSWORD %L", password)
            .await
    }

    /// Makes a superuser that can log in. Returns its name.
    pub async fn create_superuser(&mut self, password: &str) -> String {
        self.create_role_from("CREATE ROLE %I LOGIN SUPERUSER PASSWORD %L", password)
            .await
    }

    async fn create_role_from(&mut self, template: &str, password: &str) -> String {
        let name = format!("aegis_role_{}", Uuid::now_v7().simple());
        let mut connection = self.sql().await;
        let statement = formatted(&mut connection, template, &[&name, password]).await;
        connection.execute(AssertSqlSafe(statement)).await.unwrap();
        connection.close().await.unwrap();
        self.roles.push(name.clone());
        name
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let admin_url = self.server.admin_url.clone();
        let database = self.name.clone();
        let roles = std::mem::take(&mut self.roles);
        // A test can end inside a runtime, so the cleanup has its own thread and runtime.
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let mut admin = PgConnection::connect(&admin_url).await?;
                let drop_database: String = sqlx::query_scalar("SELECT pg_catalog.format($1, $2)")
                    .bind("DROP DATABASE IF EXISTS %I WITH (FORCE)")
                    .bind(&database)
                    .fetch_one(&mut admin)
                    .await?;
                admin.execute(AssertSqlSafe(drop_database)).await?;
                // The privileges of a role go away with the database. Then the role can go.
                for role in &roles {
                    let drop_role: String = sqlx::query_scalar("SELECT pg_catalog.format($1, $2)")
                        .bind("DROP ROLE IF EXISTS %I")
                        .bind(role)
                        .fetch_one(&mut admin)
                        .await?;
                    admin.execute(AssertSqlSafe(drop_role)).await?;
                }
                admin.close().await?;
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!(
                "aegis-storage docker-tests: could not drop database {}: {dropped:?}",
                self.name
            );
        }
    }
}

/// The store configuration for a test database.
pub fn config(url: &str) -> StorageConfig {
    let mut config = StorageConfig::new(url);
    config.max_connections = 8;
    config.acquire_timeout_seconds = 30;
    config
}

/// Returns the SQLSTATE code of a database error.
pub fn sqlstate(error: &sqlx::Error) -> String {
    match error {
        sqlx::Error::Database(database) => database.code().unwrap_or_default().into_owned(),
        other => panic!("expected a database error, got {other:?}"),
    }
}

/// Returns the message of a database error.
pub fn message(error: &sqlx::Error) -> String {
    match error {
        sqlx::Error::Database(database) => database.message().to_owned(),
        other => panic!("expected a database error, got {other:?}"),
    }
}
