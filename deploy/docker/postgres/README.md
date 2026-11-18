# AEGIS database image

This directory builds the database image for AEGIS: PostgreSQL 17 with Apache AGE 1.7.0 and
pgvector 0.8.6. The crate `aegis-storage` uses this database.

## Contents of the image

- The base is the official image `apache/age:release_PG17_1.7.0`.
- The pgvector files come from the official image `pgvector/pgvector:0.8.6-pg17-trixie`.
  The two images use the same PostgreSQL package and the same Debian release. Thus the build
  copies files and compiles nothing.
- Each base image has a tag and a digest. The digests are indexes for `linux/amd64` and
  `linux/arm64`.
- The directory `$libdir/plugins` has a link to the Apache AGE library. A role that is not
  a superuser can then load the library.
- The first database gets the `age` and `vector` extensions when the server makes its data
  directory.
- The default command loads Apache AGE in each session (`shared_preload_libraries=age`).

## Build

```sh
docker build --tag aegis-postgres deploy/docker/postgres
```

Build for the two platforms:

```sh
docker buildx build --platform linux/amd64,linux/arm64 --tag aegis-postgres deploy/docker/postgres
```

## Run

```sh
docker run --detach --name aegis-postgres \
    --env POSTGRES_PASSWORD=change-this-password \
    --publish 127.0.0.1:5432:5432 \
    aegis-postgres
```

The image accepts the environment variables of the official PostgreSQL image, for example
`POSTGRES_USER`, `POSTGRES_DB`, and `POSTGRES_PASSWORD`. Then run the migrations of
`aegis-storage` (`PgStore::migrate`).

For a server that is not on the same host as AEGIS, configure TLS in PostgreSQL (`ssl=on`
with a certificate for the host name) and use `sslmode=verify-full` in the database URL.

## Change a version

Change the tag and the digest of a base image together. Keep the two base images on the same
PostgreSQL major version and the same Debian release. Then build the image and run the
database tests:

```sh
cargo test -p aegis-storage --features docker-tests
```
