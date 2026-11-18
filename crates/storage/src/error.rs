//! The mapping from database errors to contract errors.
//!
//! The rules:
//!
//! - A connection problem is [`Error::Unavailable`]. A retry can succeed.
//! - A statement that the server cancels after the time limit is [`Error::Timeout`].
//! - A constraint violation or a value that the database cannot hold is
//!   [`Error::InvalidInput`].
//! - A rejected credential or a missing privilege is [`Error::Unauthorized`].
//! - A missing database, schema, table, or extension is [`Error::Config`].
//!
//! No message contains the database URL. The messages for connection and login errors
//! are fixed text, because the server text for these errors names the user and the
//! database.

use aegis_contracts::Error;
use sqlx::migrate::MigrateError;

/// The SQLSTATE of a unique constraint violation.
pub(crate) const UNIQUE_VIOLATION: &str = "23505";
/// The SQLSTATE of a missing privilege.
pub(crate) const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The largest number of characters of a server message that an error keeps.
const MAX_SERVER_MESSAGE_CHARS: usize = 200;

/// The detail of each TLS failure.
const TLS_FAILED: &str = "the TLS connection to the database failed. \
     Check sslmode and sslrootcert in the database URL";

/// The kinds of failure that the store reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The database is not available. A retry can succeed.
    Unavailable,
    /// The server stopped the statement after the time limit.
    Timeout,
    /// The database refused the data.
    InvalidInput,
    /// The database refused the credentials or the role has no privilege.
    Unauthorized,
    /// The database does not have the objects that the store needs.
    Config,
    /// A failure with no more specific kind.
    Other,
}

/// A database failure with a message that is safe to show.
#[derive(Debug, thiserror::Error)]
#[error("{operation}: {detail}")]
pub(crate) struct StorageError {
    kind: Failure,
    operation: String,
    detail: String,
}

impl StorageError {
    fn new(kind: Failure, operation: &str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            operation: operation.to_owned(),
            detail: detail.into(),
        }
    }
}

impl From<StorageError> for Error {
    fn from(error: StorageError) -> Self {
        let message = error.to_string();
        match error.kind {
            Failure::Unavailable => Self::Unavailable(message),
            Failure::Timeout => Self::Timeout(message),
            Failure::InvalidInput => Self::InvalidInput(message),
            Failure::Unauthorized => Self::Unauthorized(message),
            Failure::Config => Self::Config(message),
            Failure::Other => Self::other(error.operation, error.detail),
        }
    }
}

/// Returns the kind of failure for a PostgreSQL SQLSTATE code.
pub(crate) fn classify_sqlstate(code: &str) -> Failure {
    match code {
        // query_canceled: the statement time limit, or a cancel request.
        "57014" => Failure::Timeout,
        // insufficient_privilege.
        INSUFFICIENT_PRIVILEGE => Failure::Unauthorized,
        // invalid_catalog_name, invalid_schema_name, undefined_table, undefined_function,
        // undefined_object, undefined_file: the database, the schema, a table, a function,
        // a type, or an extension library is missing.
        "3D000" | "3F000" | "42P01" | "42883" | "42704" | "58P01" => Failure::Config,
        // serialization_failure, deadlock_detected, lock_not_available.
        "40001" | "40P01" | "55P03" => Failure::Unavailable,
        _ => match code.get(..2) {
            // Connection exception, insufficient resources, operator intervention.
            Some("08" | "53" | "57") => Failure::Unavailable,
            // Data exception, integrity constraint violation, program limit exceeded.
            Some("22" | "23" | "54") => Failure::InvalidInput,
            // Invalid authorization specification.
            Some("28") => Failure::Unauthorized,
            _ => Failure::Other,
        },
    }
}

/// Returns `true` if the server text for this SQLSTATE can name the user or the database.
fn has_sensitive_server_text(code: &str) -> bool {
    code == "3D000" || matches!(code.get(..2), Some("08" | "28"))
}

fn truncate(text: &str) -> String {
    let mut short: String = text.chars().take(MAX_SERVER_MESSAGE_CHARS).collect();
    if short.len() < text.len() {
        short.push_str("...");
    }
    short
}

/// Makes the error for a failure that the database server reported.
pub(crate) fn server_error(
    operation: &str,
    code: &str,
    constraint: Option<&str>,
    message: &str,
) -> StorageError {
    let kind = classify_sqlstate(code);
    let detail = if has_sensitive_server_text(code) {
        match kind {
            Failure::Unauthorized => {
                format!("the database rejected the credentials (SQLSTATE {code})")
            }
            Failure::Config => {
                format!("the database in the URL does not exist (SQLSTATE {code})")
            }
            _ => format!("the database connection failed (SQLSTATE {code})"),
        }
    } else {
        let hint = match code {
            "3F000" | "42P01" | "42883" | "42704" => {
                " Run the migrations with a role that owns the AEGIS schema."
            }
            "58P01" => " Use a server that has the Apache AGE and pgvector extensions.",
            _ => "",
        };
        match constraint {
            Some(name) => format!(
                "{} (SQLSTATE {code}, constraint {name}).{hint}",
                truncate(message)
            ),
            None => format!("{} (SQLSTATE {code}).{hint}", truncate(message)),
        }
    };
    StorageError::new(kind, operation, detail)
}

fn storage_error(operation: &str, error: sqlx::Error) -> StorageError {
    match error {
        sqlx::Error::Database(database) => {
            let code = database.code().map(|code| code.into_owned());
            server_error(
                operation,
                code.as_deref().unwrap_or_default(),
                database.constraint(),
                database.message(),
            )
        }
        // The TLS library reports a failed handshake, for example a certificate that it
        // does not trust, as an input error of this kind. The text of that error can name
        // the host, so the message here is fixed text.
        sqlx::Error::Io(io) if io.kind() == std::io::ErrorKind::InvalidData => {
            StorageError::new(Failure::Unavailable, operation, TLS_FAILED)
        }
        // The driver reads the certificate files and opens the socket that the URL names.
        sqlx::Error::Io(io) if io.kind() == std::io::ErrorKind::NotFound => StorageError::new(
            Failure::Unavailable,
            operation,
            "the database connection failed. \
             A socket or a certificate file that the database URL names does not exist",
        ),
        sqlx::Error::Io(io) => StorageError::new(
            Failure::Unavailable,
            operation,
            format!("the database connection failed ({})", io.kind()),
        ),
        sqlx::Error::Tls(_) => StorageError::new(Failure::Unavailable, operation, TLS_FAILED),
        sqlx::Error::PoolTimedOut => StorageError::new(
            Failure::Unavailable,
            operation,
            "no database connection became available in the permitted time",
        ),
        sqlx::Error::PoolClosed => {
            StorageError::new(Failure::Unavailable, operation, "the store is closed")
        }
        sqlx::Error::WorkerCrashed | sqlx::Error::Protocol(_) | sqlx::Error::BeginFailed => {
            StorageError::new(
                Failure::Unavailable,
                operation,
                "the database connection is broken",
            )
        }
        sqlx::Error::Configuration(_) => StorageError::new(
            Failure::Config,
            operation,
            "the database connection settings are not valid",
        ),
        sqlx::Error::TypeNotFound { type_name } => StorageError::new(
            Failure::Config,
            operation,
            format!(
                "the database has no type {type_name}. \
                 Run the migrations with a role that owns the AEGIS schema"
            ),
        ),
        sqlx::Error::Migrate(migrate) => migrate_storage_error(operation, *migrate),
        other => StorageError::new(Failure::Other, operation, other.to_string()),
    }
}

fn migrate_storage_error(operation: &str, error: MigrateError) -> StorageError {
    match error {
        MigrateError::Execute(source) => storage_error(operation, source),
        MigrateError::ExecuteMigration(source, version) => {
            let mut inner = storage_error(operation, source);
            inner.detail = format!("migration {version}: {}", inner.detail);
            inner
        }
        other => StorageError::new(
            Failure::Config,
            operation,
            format!("the database schema does not agree with this version of AEGIS: {other}"),
        ),
    }
}

/// Maps a database error to a contract error. `operation` names what the store did.
pub(crate) fn db_error(operation: &str, error: sqlx::Error) -> Error {
    storage_error(operation, error).into()
}

/// Maps a migration error to a contract error.
pub(crate) fn migrate_error(operation: &str, error: MigrateError) -> Error {
    migrate_storage_error(operation, error).into()
}

/// Maps a row that the store cannot decode to a contract error.
pub(crate) fn decode_error(what: &str, error: impl std::fmt::Display) -> Error {
    Error::Serialization(format!("storage: {what} cannot be decoded: {error}"))
}

/// Returns the SQLSTATE code of a database error.
pub(crate) fn sqlstate(error: &sqlx::Error) -> Option<String> {
    match error {
        sqlx::Error::Database(database) => database.code().map(|code| code.into_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn sqlstate_codes_map_to_the_documented_kinds() {
        let cases = [
            ("08006", Failure::Unavailable),
            ("08001", Failure::Unavailable),
            ("53300", Failure::Unavailable),
            ("57P01", Failure::Unavailable),
            ("57P03", Failure::Unavailable),
            ("40001", Failure::Unavailable),
            ("40P01", Failure::Unavailable),
            ("55P03", Failure::Unavailable),
            ("57014", Failure::Timeout),
            ("23505", Failure::InvalidInput),
            ("23503", Failure::InvalidInput),
            ("23514", Failure::InvalidInput),
            ("23000", Failure::InvalidInput),
            ("22003", Failure::InvalidInput),
            ("22021", Failure::InvalidInput),
            ("54000", Failure::InvalidInput),
            ("28P01", Failure::Unauthorized),
            ("28000", Failure::Unauthorized),
            ("42501", Failure::Unauthorized),
            ("3D000", Failure::Config),
            ("3F000", Failure::Config),
            ("42P01", Failure::Config),
            ("42883", Failure::Config),
            ("58P01", Failure::Config),
            ("42601", Failure::Other),
            ("XX000", Failure::Other),
            ("", Failure::Other),
        ];
        for (code, expected) in cases {
            assert_eq!(classify_sqlstate(code), expected, "SQLSTATE {code}");
        }
    }

    #[test]
    fn a_constraint_violation_is_invalid_input_with_the_constraint_name() {
        let error: Error = server_error(
            "save the approval request",
            "23505",
            Some("approvals_pkey"),
            "duplicate key value violates unique constraint \"approvals_pkey\"",
        )
        .into();
        match error {
            Error::InvalidInput(message) => assert_eq!(
                message,
                "save the approval request: duplicate key value violates unique constraint \
                 \"approvals_pkey\" (SQLSTATE 23505, constraint approvals_pkey)."
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn login_errors_do_not_repeat_the_server_text() {
        let rejected: Error = server_error(
            "connect to the database",
            "28P01",
            None,
            "password authentication failed for user \"aegis_admin\"",
        )
        .into();
        match rejected {
            Error::Unauthorized(message) => assert_eq!(
                message,
                "connect to the database: the database rejected the credentials (SQLSTATE 28P01)"
            ),
            other => panic!("expected Unauthorized, got {other:?}"),
        }

        let missing: Error = server_error(
            "connect to the database",
            "3D000",
            None,
            "database \"tenant_secret_name\" does not exist",
        )
        .into();
        match missing {
            Error::Config(message) => assert_eq!(
                message,
                "connect to the database: the database in the URL does not exist (SQLSTATE 3D000)"
            ),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_table_tells_the_operator_to_run_the_migrations() {
        let error: Error = server_error(
            "read the incident",
            "42P01",
            None,
            "relation \"aegis.incidents\" does not exist",
        )
        .into();
        match error {
            Error::Config(message) => {
                assert!(
                    message.ends_with("Run the migrations with a role that owns the AEGIS schema.")
                );
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn a_long_server_message_is_cut() {
        let long = "x".repeat(5_000);
        let error: Error = server_error("write the node", "22023", None, &long).into();
        match error {
            Error::InvalidInput(message) => {
                assert!(message.len() < 300, "{}", message.len());
                assert!(message.contains("xxx... (SQLSTATE 22023)"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn connection_failures_are_retryable() {
        let refused = db_error(
            "read the node",
            sqlx::Error::Io(io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
        );
        match &refused {
            Error::Unavailable(message) => assert_eq!(
                message,
                "read the node: the database connection failed (connection refused)"
            ),
            other => panic!("expected Unavailable, got {other:?}"),
        }
        assert!(refused.is_retryable());

        for error in [sqlx::Error::PoolTimedOut, sqlx::Error::PoolClosed] {
            let mapped = db_error("read the node", error);
            assert!(matches!(mapped, Error::Unavailable(_)), "{mapped:?}");
        }
    }

    #[test]
    fn a_missing_file_from_the_url_is_named_as_the_cause_without_its_path() {
        let missing = sqlx::Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "/etc/aegis/secret-ca.pem: No such file or directory",
        ));
        match db_error("connect to the database", missing) {
            Error::Unavailable(message) => assert_eq!(
                message,
                "connect to the database: the database connection failed. \
                 A socket or a certificate file that the database URL names does not exist"
            ),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn tls_failures_have_fixed_text_and_do_not_repeat_the_cause() {
        let handshake = sqlx::Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer certificate: certificate not valid for name db.internal.example",
        ));
        let no_tls = sqlx::Error::Tls("server at db.internal.example does not support TLS".into());
        for error in [handshake, no_tls] {
            let mapped = db_error("connect to the database", error);
            match &mapped {
                Error::Unavailable(message) => assert_eq!(
                    message,
                    "connect to the database: the TLS connection to the database failed. \
                     Check sslmode and sslrootcert in the database URL"
                ),
                other => panic!("expected Unavailable, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_code_keeps_the_operation_and_the_server_text() {
        let error: Error =
            server_error("write the node", "XX000", None, "unexpected internal state").into();
        match error {
            Error::Other { context, source } => {
                assert_eq!(context, "write the node");
                assert_eq!(
                    source.to_string(),
                    "unexpected internal state (SQLSTATE XX000)."
                );
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn a_changed_migration_is_a_configuration_error() {
        let error = migrate_error("run the migrations", MigrateError::VersionMismatch(3));
        match error {
            Error::Config(message) => assert!(message.contains("migration 3"), "{message}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }
}
