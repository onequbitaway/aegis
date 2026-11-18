-- Adds pgvector to the first database. The AEGIS migrations use the extension.
CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;
