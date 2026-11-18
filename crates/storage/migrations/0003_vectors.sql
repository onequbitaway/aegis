-- Embeddings in pgvector.
--
-- The first record of a collection sets the number of dimensions of the collection.
-- The foreign key and the check make a different number of dimensions impossible.

CREATE TABLE IF NOT EXISTS aegis.vector_collections (
    name       text    PRIMARY KEY,
    dimensions integer NOT NULL CHECK (dimensions BETWEEN 1 AND 16000),
    UNIQUE (name, dimensions)
);

CREATE TABLE IF NOT EXISTS aegis.vectors (
    collection text        NOT NULL,
    id         text        NOT NULL,
    dimensions integer     NOT NULL,
    embedding  vector      NOT NULL,
    content    text        NOT NULL,
    -- The metadata as JSON text. Text keeps each number as the application wrote it.
    metadata   text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (collection, id),
    FOREIGN KEY (collection, dimensions)
        REFERENCES aegis.vector_collections (name, dimensions),
    CHECK (vector_dims(embedding) = dimensions)
);
