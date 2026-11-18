# The AEGIS database image: PostgreSQL 17 with Apache AGE 1.7.0 and pgvector 0.8.6.
#
# The two base images are official builds for the same PostgreSQL package and the same
# Debian release. Thus the build copies the pgvector files and compiles nothing.
# Each base image has a tag and a digest. The digest is a multi-platform index, so the
# build gives the same result for linux/amd64 and linux/arm64.
#
# To change a version, change the tag and the digest together. Keep the two base images
# on the same PostgreSQL major version and the same Debian release.

ARG PG_MAJOR=17

FROM pgvector/pgvector:0.8.6-pg17-trixie@sha256:724a4041afdb1750446e3f6b5cfa8f3b0ac5a2cf538ddfa6bfee4f94c2fa85c6 AS pgvector

FROM apache/age:release_PG17_1.7.0@sha256:92a5d223965bc2e436f9eee436e0bd2c0d81f3b59124b3d197ec94706f3450a8

ARG PG_MAJOR

LABEL org.opencontainers.image.title="aegis-postgres" \
      org.opencontainers.image.description="PostgreSQL with Apache AGE and pgvector for AEGIS storage" \
      org.opencontainers.image.source="https://github.com/onequbitaway/aegis" \
      org.opencontainers.image.licenses="PostgreSQL AND Apache-2.0"

COPY --from=pgvector /usr/lib/postgresql/${PG_MAJOR}/lib/vector.so /usr/lib/postgresql/${PG_MAJOR}/lib/vector.so
COPY --from=pgvector /usr/lib/postgresql/${PG_MAJOR}/lib/bitcode/vector /usr/lib/postgresql/${PG_MAJOR}/lib/bitcode/vector
COPY --from=pgvector /usr/lib/postgresql/${PG_MAJOR}/lib/bitcode/vector.index.bc /usr/lib/postgresql/${PG_MAJOR}/lib/bitcode/vector.index.bc
COPY --from=pgvector /usr/share/postgresql/${PG_MAJOR}/extension/vector.control /usr/share/postgresql/${PG_MAJOR}/extension/
COPY --from=pgvector /usr/share/postgresql/${PG_MAJOR}/extension/vector--*.sql /usr/share/postgresql/${PG_MAJOR}/extension/
COPY --from=pgvector /usr/share/doc/pgvector /usr/share/doc/pgvector

# A role that is not a superuser can load a library only from `$libdir/plugins`.
# This link lets the AEGIS application role run `LOAD '$libdir/plugins/age'`.
RUN mkdir -p /usr/lib/postgresql/${PG_MAJOR}/lib/plugins \
    && ln -s ../age.so /usr/lib/postgresql/${PG_MAJOR}/lib/plugins/age.so

# The base image creates the `age` extension in the first database.
# This script adds the `vector` extension to the same database.
COPY initdb/10-create-extension-vector.sql /docker-entrypoint-initdb.d/10-create-extension-vector.sql

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD pg_isready --host=127.0.0.1 --username="${POSTGRES_USER:-postgres}" --dbname="${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"

CMD ["postgres", "-c", "shared_preload_libraries=age"]
