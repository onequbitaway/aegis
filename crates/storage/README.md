# aegis-storage

PostgreSQL storage for AEGIS. One database holds all durable state:

- The Defensive Graph, in [Apache AGE](https://age.apache.org).
- Embeddings, in [pgvector](https://github.com/pgvector/pgvector).
- Incidents, the hash-chained audit log, and the approval queue, in tables.

The crate implements the storage contracts of `aegis-contracts`. Other crates use the
contracts and do not call PostgreSQL directly.

## Public API

| Item | Contract | Storage |
| --- | --- | --- |
| `StorageConfig` | | The database URL and the pool settings. |
| `PgStore` | | The connection pool. It gives the repositories. |
| `PgGraph` | `DefensiveGraph` | The Apache AGE graph `aegis_graph`. |
| `PgVectors` | `VectorStore` | The tables `aegis.vectors` and `aegis.vector_collections`. |
| `PgIncidents` | `IncidentStore` | The table `aegis.incidents`. |
| `PgAuditLog` | `AuditLog` | The table `aegis.audit_log`. |
| `PgApprovals` | `ApprovalQueue` | The table `aegis.approvals`. |

`PgStore` has these functions:

| Function | Operation |
| --- | --- |
| `PgStore::connect(&config)` | Checks the configuration and opens the pool. |
| `store.migrate()` | Makes or updates the schema. It is safe to call again. |
| `store.ping()` | Checks that the database answers. |
| `store.close()` | Closes all connections. |
| `store.graph()`, `store.vectors()`, `store.incidents()`, `store.audit()`, `store.approvals()` | Give the repositories. |

`PgGraph` also has `node_count()`, `edge_count()`, and `edge(from, relation, to)`.

A store and its repositories are cheap to clone. All clones use one pool.

```rust
use std::sync::Arc;

use aegis_contracts::{AuditLog, DefensiveGraph};
use aegis_storage::{PgStore, StorageConfig};

async fn open(url: &str) -> aegis_contracts::Result<(Arc<dyn DefensiveGraph>, Arc<dyn AuditLog>)> {
    // For example: postgres://aegis:password@db.example/aegis?sslmode=verify-full
    let store = PgStore::connect(&StorageConfig::new(url)).await?;
    store.migrate().await?;
    Ok((Arc::new(store.graph()), Arc::new(store.audit())))
}
```

## Configuration

`StorageConfig` implements `serde::Deserialize`. An unknown field is an error.

| Field | Default | Meaning |
| --- | --- | --- |
| `url` | (necessary) | The database URL. The URL is a secret. |
| `max_connections` | 10 | The largest number of open connections. |
| `min_connections` | 0 | The number of connections that the pool keeps open. |
| `acquire_timeout_seconds` | 10 | The time to wait for a connection. |
| `statement_timeout_seconds` | 30 | The time limit of one statement. The value 0 sets no limit. |

The URL has the form `postgres://user:password@host:port/database?parameter=value`. The
store accepts these parameters: `sslmode`, `sslrootcert`, `sslcert`, `sslkey`,
`application_name`, `options`, and `statement-cache-capacity`. A different parameter is a
configuration error.

The database driver also reads the `PG*` environment variables of libpq, for example
`PGSSLMODE` and `PGSSLROOTCERT`. A value in the URL has priority.

### TLS

The store uses rustls. The `sslmode` parameter of the URL selects TLS:

| `sslmode` | Result |
| --- | --- |
| `disable` | No TLS. |
| `prefer` (default) | TLS if the server has it. The certificate is not checked. |
| `require` | TLS. The certificate is not checked. |
| `verify-ca` | TLS. The certificate must come from a trusted authority. |
| `verify-full` | TLS. The certificate must come from a trusted authority and must name the host. |

Use `verify-full` for each server that is not on the same host. The trusted authorities are
the Mozilla root certificates. For a private authority, add `sslrootcert=/path/ca.pem`. The
store writes a warning to the log if a connection to a remote host does not check the
certificate.

### The URL is a secret

No error message and no log line of this crate contains the URL or a part of it. The `Debug`
output of `StorageConfig` and of the store does not show it. The messages for connection
errors and login errors are fixed text, because the server text for these errors names the
user and the database.

## Database server

The server must have PostgreSQL with the `age` and `vector` extensions.
`deploy/docker/postgres/Dockerfile` builds an image with PostgreSQL 17, Apache AGE 1.7.0, and
pgvector 0.8.6 for `linux/amd64` and `linux/arm64`. Refer to
[`deploy/docker/postgres/README.md`](../../deploy/docker/postgres/README.md).

Each connection of the store loads Apache AGE and sets the search path to
`public, ag_catalog`. A role that is not a superuser can load the library only from the
`plugins` directory of the server. The image has a link to the library there.

The `vector` extension must be in the schema `public`. The migrations make it there.

## Schema and migrations

The crate embeds its SQL migrations (the files in `migrations/`). `store.migrate()` runs
them in order, one transaction for each migration. The table `aegis.storage_migrations`
records the migrations that ran. A second call changes nothing. Several processes can call
`migrate()` at the same time.

Run the migrations with a role that owns the schema. To create the `age` extension, the
role must be a superuser. Never change a migration after a release. Add a file with the
next number.

| Object | Contents |
| --- | --- |
| Graph `aegis_graph` | One vertex label, `Node`. One edge label for each relation name. |
| `aegis.vector_collections`, `aegis.vectors` | The number of dimensions of each collection, and the records. |
| `aegis.incidents` | One row for each incident. The `document` column holds the incident as JSON text. |
| `aegis.audit_log` | One row for each audit record. |
| `aegis.approvals` | One row for each approval request. |

## Behavior of each repository

### Defensive Graph

- Each statement is openCypher through the `cypher()` function of Apache AGE.
- Each value goes to the database in the `agtype` parameter map of the call. No statement
  contains a value.
- A relation name becomes an edge label, and Cypher does not let a label be a parameter.
  The graph accepts only names that match `^[a-z][a-z0-9_]*$` with at most 48 characters.
  A different name is `Error::InvalidInput`.
- `upsert_node` replaces all fields of a node with the same identifier.
- `upsert_edge` replaces the properties of a relation with the same start, end, and name.
  If the start node or the end node does not exist, the result is `Error::NotFound`.
- `neighbors` gives each neighbor one time, in the order of the first write of the relations.
- `nodes_by_kind` gives the newest nodes first. The order uses the full time, with
  nanoseconds.
- A node identifier can have 1024 bytes. A property value cannot be an integer larger than
  the largest 64-bit signed integer, and text cannot contain the character U+0000. These
  values are `Error::InvalidInput`.
- Each write takes an advisory lock for its node or its relation, because Apache AGE fails
  a statement that changes an item which a different session changes at the same time.

### Vector store

- The first record of a collection sets the number of dimensions of the collection.
- An empty embedding, a value that is not finite, or a different number of dimensions is
  `Error::InvalidInput`. The check applies to `upsert` and to `search`.
- `search` gives the nearest records first. The score is the cosine similarity. The score of
  a vector of zero length is 0.
- The search is exact. It reads all records of the collection. There is no index for the
  vector order.

### Incident store

- `save` replaces an incident with the same identifier.
- `list` gives the newest incidents first, by creation time with nanoseconds.

### Audit log

- `append` seals each record with `aegis_contracts::audit::seal`.
- An append runs in one transaction. The transaction takes an advisory lock, reads the last
  record, and writes the next record. Thus the appends of all processes make one chain.
- The time of a record is the clock of the database server.
- The table keeps each field byte for byte. The payload and the evidence are JSON text, not
  `jsonb`. The time has microsecond precision.
- `verify` reads the full table and runs `aegis_contracts::audit::verify_chain`.
- A trigger rejects each `UPDATE`, `DELETE`, and `TRUNCATE` on the table. A second trigger
  rejects a record that does not continue the chain.

### Approval queue

- `pending` gives the oldest requests first.
- `decide` changes the state with one `UPDATE` statement that also checks that the request
  is pending. Only one of two decisions at the same time can succeed. The other decision is
  `Error::InvalidInput`. A request that does not exist is `Error::NotFound`.
- A trigger rejects each change of a request that has a decision.
- `submit` accepts only a pending request. `submit` does not replace a request with the same
  identifier: a different request with that identifier is `Error::InvalidInput`. A second
  submit of the same pending request changes nothing, so a caller can submit again after a
  connection failure. The in-memory queue of the test kit replaces the request instead.

### Errors

| Database condition | Contract error |
| --- | --- |
| Connection failure, TLS failure, closed store, no free connection | `Unavailable` |
| Statement stopped after the time limit | `Timeout` |
| Constraint violation, or a value that the database cannot hold | `InvalidInput` |
| Rejected login, or a missing privilege | `Unauthorized` |
| Missing database, schema, table, type, or extension | `Config` |
| A stored row that cannot be decoded | `Serialization` (`Integrity` for the audit log) |

## Roles and privileges

The role that runs the migrations owns the schema. The application can use a role with
fewer privileges. The application role needs only `INSERT` and `SELECT` on the audit table,
so that it cannot change or remove a record. Give the application role these privileges
(replace `aegis_app`):

```sql
GRANT USAGE ON SCHEMA aegis, aegis_graph, ag_catalog TO aegis_app;
GRANT SELECT, INSERT ON aegis.audit_log TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON aegis.incidents, aegis.approvals, aegis.vectors TO aegis_app;
GRANT SELECT, INSERT ON aegis.vector_collections TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA aegis_graph TO aegis_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA aegis_graph TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA aegis_graph
    GRANT SELECT, INSERT, UPDATE ON TABLES TO aegis_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA aegis_graph
    GRANT USAGE ON SEQUENCES TO aegis_app;
```

Run the two `ALTER DEFAULT PRIVILEGES` statements as the role that owns the schema.

The migrations make the edge labels for the relation names of `aegis_contracts::graph::relation`.
The application role cannot make an edge label. For a different relation name, run this
statement one time as the role that owns the schema:

```sql
SELECT aegis.ensure_relation('reported_by');
```

The triggers on the audit table stop a role that has more privileges than necessary. The
owner of the table and a superuser can switch a trigger off. The hash chain finds a change
that such a role makes: `verify()` gives the first record that is not correct.

## Advisory locks

The store uses these PostgreSQL advisory locks in the AEGIS database. All are transaction
locks with two keys.

| First key | Second key | Use |
| --- | --- | --- |
| `0x61656769` | 1 | One append to the audit log at a time. |
| `0x61656769` | 2 | One new edge label at a time. |
| `0x6165676E` | Hash of the node identifier | One write to a node at a time. |
| `0x61656765` | Hash of the start, the name, and the end | One write to a relation at a time. |

## Test

The unit tests need no database:

```sh
cargo test -p aegis-storage
```

The tests of the contracts against a real database are behind the feature `docker-tests`:

```sh
cargo test -p aegis-storage --features docker-tests
```

With the feature, the tests build the image from `deploy/docker/postgres/Dockerfile` and
start one container on a free port of this host. Each test makes its own database, so the
tests run in parallel. The tests remove the container when the last test completes. A
watchdog in the container also stops it when the test process goes away early.

To use a server that is already in operation, set `AEGIS_TEST_DATABASE_URL`. The tests then
start no container.

```sh
AEGIS_TEST_DATABASE_URL=postgres://postgres:password@127.0.0.1:5432/postgres \
    cargo test -p aegis-storage --features docker-tests
```

The server in the variable must have the `age` and `vector` extensions and password
authentication. The role in the URL must be a superuser. The tests make and remove databases
and roles with the prefixes `aegis_test_` and `aegis_role_`.

If Docker is not available and the variable is not set, each test fails with a message that
tells you what to do.

With `--test-threads=1`, each test starts its own container. Set `AEGIS_TEST_DATABASE_URL`
when you run the tests one at a time.

To find a container that a stopped test run did not remove:

```sh
docker ps --filter label=aegis.test=storage
```
