//! The SQL migrations of the store. The crate embeds each file at compile time.

use std::borrow::Cow;

use sqlx::SqlSafeStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};

/// The schema that holds the AEGIS tables.
const SCHEMA: &str = "aegis";

/// The table that records which migrations ran.
///
/// The table is in the AEGIS schema, so that a different application in the same database
/// cannot mix its migrations with these.
const MIGRATIONS_TABLE: &str = "aegis.storage_migrations";

/// One embedded migration: the version, the description, and the SQL text.
pub(crate) struct EmbeddedMigration {
    pub(crate) version: i64,
    pub(crate) description: &'static str,
    pub(crate) sql: &'static str,
}

/// All migrations, in version order.
///
/// Never change a migration after a release. Add a new file with the next version.
pub(crate) const MIGRATIONS: &[EmbeddedMigration] = &[
    EmbeddedMigration {
        version: 1,
        description: "extensions",
        sql: include_str!("../migrations/0001_extensions.sql"),
    },
    EmbeddedMigration {
        version: 2,
        description: "graph",
        sql: include_str!("../migrations/0002_graph.sql"),
    },
    EmbeddedMigration {
        version: 3,
        description: "vectors",
        sql: include_str!("../migrations/0003_vectors.sql"),
    },
    EmbeddedMigration {
        version: 4,
        description: "incidents",
        sql: include_str!("../migrations/0004_incidents.sql"),
    },
    EmbeddedMigration {
        version: 5,
        description: "audit log",
        sql: include_str!("../migrations/0005_audit_log.sql"),
    },
    EmbeddedMigration {
        version: 6,
        description: "approvals",
        sql: include_str!("../migrations/0006_approvals.sql"),
    },
];

/// Makes the migrator for the embedded migrations.
pub(crate) fn migrator() -> Migrator {
    let migrations = MIGRATIONS
        .iter()
        .map(|migration| {
            Migration::new(
                migration.version,
                Cow::Borrowed(migration.description),
                MigrationType::Simple,
                migration.sql.into_sql_str(),
                false,
            )
        })
        .collect();
    let mut migrator = Migrator::with_migrations(migrations);
    migrator.create_schema(SCHEMA);
    migrator.dangerous_set_table_name(MIGRATIONS_TABLE);
    migrator
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::*;

    #[test]
    fn versions_start_at_one_and_increase_by_one() {
        let versions: Vec<i64> = MIGRATIONS
            .iter()
            .map(|migration| migration.version)
            .collect();
        let expected: Vec<i64> = (1..=i64::try_from(MIGRATIONS.len()).unwrap()).collect();
        assert!(!versions.is_empty());
        assert_eq!(versions, expected);
    }

    #[test]
    fn each_file_in_the_migrations_directory_is_embedded() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let on_disk: BTreeSet<String> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        let embedded: BTreeSet<String> = MIGRATIONS
            .iter()
            .map(|migration| {
                format!(
                    "{:04}_{}.sql",
                    migration.version,
                    migration.description.replace(' ', "_")
                )
            })
            .collect();
        assert_eq!(embedded.len(), MIGRATIONS.len());
        assert_eq!(on_disk, embedded);
    }

    #[test]
    fn the_migrator_runs_each_migration_in_a_transaction() {
        let migrator = migrator();
        let versions: Vec<i64> = migrator.iter().map(|migration| migration.version).collect();
        assert_eq!(versions, [1, 2, 3, 4, 5, 6]);
        assert!(migrator.iter().all(|migration| !migration.no_tx));
    }
}
