//! The store: the connection pool, the connection setup, and the migrations.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aegis_contracts::{Error, Result};
use sqlx::postgres::{PgConnection, PgPool, PgPoolOptions};
use sqlx::{ConnectOptions, Connection, Executor};

use crate::approvals::PgApprovals;
use crate::audit::PgAuditLog;
use crate::config::{StorageConfig, is_local, verifies_server};
use crate::error::{INSUFFICIENT_PRIVILEGE, db_error, migrate_error, sqlstate};
use crate::graph::PgGraph;
use crate::incidents::PgIncidents;
use crate::migrations::migrator;
use crate::vectors::PgVectors;

/// Reads if the role of the session is a superuser.
const IS_SUPERUSER: &str = "SELECT pg_catalog.current_setting('is_superuser') = 'on'";

/// Loads Apache AGE in a session of a superuser.
const LOAD_AGE: &str = "LOAD 'age'";

/// Loads Apache AGE in a session of a role that is not a superuser.
///
/// PostgreSQL lets such a role load a library only from `$libdir/plugins`. The AEGIS
/// database image has a link to the library there.
const LOAD_AGE_FROM_PLUGINS: &str = "LOAD '$libdir/plugins/age'";

/// The schema search path of each session.
///
/// Apache AGE needs `ag_catalog` in the path. The pgvector type and operators are in
/// `public`. The path does not have the schema with the name of the role, so each role
/// finds the same objects.
const SET_SEARCH_PATH: &str = "SET search_path = public, ag_catalog";

/// Sets the isolation level of each transaction that names no level.
///
/// The store needs this level: a statement must see each change that a different session
/// committed before the statement started.
const SET_ISOLATION: &str = "SET default_transaction_isolation = 'read committed'";

/// Sets the statement time limit of the session. The value is a bound parameter.
const SET_STATEMENT_TIMEOUT: &str = "SELECT pg_catalog.set_config('statement_timeout', $1, false)";

/// The relation names for which this process already made the edge label.
#[derive(Debug, Default)]
pub(crate) struct RelationCache(Mutex<HashSet<String>>);

impl RelationCache {
    pub(crate) fn contains(&self, relation: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(relation)
    }

    pub(crate) fn insert(&self, relation: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(relation.to_owned());
    }
}

/// The PostgreSQL store of AEGIS.
///
/// A store is cheap to clone. All clones use the same connection pool.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
    relations: Arc<RelationCache>,
}

impl PgStore {
    /// Connects to the database.
    ///
    /// The function opens one connection and prepares it, so that a wrong URL, a rejected
    /// credential, or a server without Apache AGE fails here and not later. The function
    /// does not change the database. Call [`PgStore::migrate`] to make the schema.
    ///
    /// The URL selects TLS with its `sslmode` parameter. The store uses rustls.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`]: the configuration is not valid, the database does not exist, or
    ///   the server cannot load Apache AGE.
    /// - [`Error::Unauthorized`]: the server rejected the credentials.
    /// - [`Error::Unavailable`]: the server is not reachable.
    ///
    /// No error contains the database URL.
    pub async fn connect(config: &StorageConfig) -> Result<Self> {
        const OPERATION: &str = "connect to the database";

        let options = config.connect_options()?;
        if !verifies_server(&options) && !is_local(&options) {
            tracing::warn!(
                "The database connection does not check the server certificate. \
                 Set sslmode=verify-full in the database URL."
            );
        }
        let statement_timeout = Duration::from_secs(config.statement_timeout_seconds);

        let probe = async {
            let mut connection = options
                .connect()
                .await
                .map_err(|error| db_error(OPERATION, error))?;
            prepare_connection(&mut connection, statement_timeout)
                .await
                .map_err(|error| setup_error(OPERATION, error))?;
            connection
                .close()
                .await
                .map_err(|error| db_error(OPERATION, error))
        };
        match tokio::time::timeout(config.acquire_timeout(), probe).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(Error::Unavailable(format!(
                    "{OPERATION}: the server did not answer in {} seconds",
                    config.acquire_timeout_seconds
                )));
            }
        }

        let pool = pool_options(config, statement_timeout).connect_lazy_with(options);
        Ok(Self {
            pool,
            relations: Arc::new(RelationCache::default()),
        })
    }

    /// Makes or updates the database schema.
    ///
    /// The function creates the `age` and `vector` extensions, the graph, and the tables.
    /// It is safe to call again, and safe to call from several processes at the same time.
    /// Use a role that owns the database objects. To create the `age` extension, the role
    /// must be a superuser.
    ///
    /// # Errors
    ///
    /// - [`Error::Unauthorized`]: the role has no privilege to change the schema.
    /// - [`Error::Config`]: the database has a schema from a different version of AEGIS.
    /// - [`Error::Unavailable`]: the server is not reachable.
    pub async fn migrate(&self) -> Result<()> {
        migrator()
            .run(&self.pool)
            .await
            .map_err(|error| migrate_error("run the migrations", error))
    }

    /// Checks that the database answers.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|error| db_error("check the database", error))
    }

    /// Closes all connections. Each later operation returns [`Error::Unavailable`].
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Returns the Defensive Graph.
    #[must_use]
    pub fn graph(&self) -> PgGraph {
        PgGraph::new(self.pool.clone(), Arc::clone(&self.relations))
    }

    /// Returns the vector store.
    #[must_use]
    pub fn vectors(&self) -> PgVectors {
        PgVectors::new(self.pool.clone())
    }

    /// Returns the incident store.
    #[must_use]
    pub fn incidents(&self) -> PgIncidents {
        PgIncidents::new(self.pool.clone())
    }

    /// Returns the audit log.
    #[must_use]
    pub fn audit(&self) -> PgAuditLog {
        PgAuditLog::new(self.pool.clone())
    }

    /// Returns the approval queue.
    #[must_use]
    pub fn approvals(&self) -> PgApprovals {
        PgApprovals::new(self.pool.clone())
    }
}

fn pool_options(config: &StorageConfig, statement_timeout: Duration) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(config.acquire_timeout())
        .after_connect(move |connection, _metadata| {
            Box::pin(prepare_connection(connection, statement_timeout))
        })
}

/// Prepares one new connection: loads Apache AGE and sets the session parameters.
async fn prepare_connection(
    connection: &mut PgConnection,
    statement_timeout: Duration,
) -> std::result::Result<(), sqlx::Error> {
    let superuser: bool = sqlx::query_scalar(IS_SUPERUSER)
        .fetch_one(&mut *connection)
        .await?;
    let load = if superuser {
        LOAD_AGE
    } else {
        LOAD_AGE_FROM_PLUGINS
    };
    connection.execute(load).await?;
    connection.execute(SET_SEARCH_PATH).await?;
    connection.execute(SET_ISOLATION).await?;
    sqlx::query(SET_STATEMENT_TIMEOUT)
        .bind(format!("{}s", statement_timeout.as_secs()))
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// Maps a failure of the connection setup. A server that cannot load Apache AGE is a
/// configuration error, not a missing privilege of the caller.
fn setup_error(operation: &str, error: sqlx::Error) -> Error {
    match sqlstate(&error).as_deref() {
        Some(INSUFFICIENT_PRIVILEGE | "58P01") => Error::Config(format!(
            "{operation}: the server cannot load the Apache AGE library for this role. \
             Use the AEGIS database image, or link age.so in the plugins directory of the server"
        )),
        _ => db_error(operation, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_relation_cache_remembers_each_name() {
        let cache = RelationCache::default();
        assert!(!cache.contains("owns"));
        cache.insert("owns");
        assert!(cache.contains("owns"));
        assert!(!cache.contains("has_role"));
    }

    #[tokio::test]
    async fn a_closed_port_is_unavailable_and_the_error_hides_the_url() {
        // Take a free port, then close it. Nothing listens there.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mut config = StorageConfig::new(format!(
            "postgres://aegis:hunter2-secret@127.0.0.1:{port}/aegis"
        ));
        config.acquire_timeout_seconds = 5;
        let error = PgStore::connect(&config).await.unwrap_err();
        match &error {
            Error::Unavailable(message) => {
                assert_eq!(
                    message,
                    "connect to the database: the database connection failed (connection refused)"
                );
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
        assert!(error.is_retryable());
    }

    #[tokio::test]
    async fn an_invalid_url_fails_before_any_connection() {
        let error = PgStore::connect(&StorageConfig::new("not a url"))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Config(_)), "{error:?}");
    }
}
