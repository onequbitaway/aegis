-- Extensions and the schema for the AEGIS tables.
--
-- Apache AGE holds the Defensive Graph. pgvector holds the embeddings.
-- A role that cannot create an extension can run this migration only if the two
-- extensions are already in the database. The AEGIS database image makes them.

CREATE EXTENSION IF NOT EXISTS age;

-- Each session of the store has the schema `public` in its search path. A fixed schema
-- makes the pgvector type and operators available to each role.
CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS aegis;
