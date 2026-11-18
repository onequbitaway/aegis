-- Incidents.
--
-- The `document` column holds the full incident as JSON text. It is the source of truth.
-- The other columns are copies for filters and for the sort order.

CREATE TABLE IF NOT EXISTS aegis.incidents (
    id         uuid        PRIMARY KEY,
    status     text        NOT NULL,
    severity   text        NOT NULL,
    tenant     text,
    -- The creation time, rounded down to microseconds.
    created_at timestamptz NOT NULL,
    -- The nanoseconds of the creation time that `created_at` cannot keep.
    created_at_nanos smallint NOT NULL CHECK (created_at_nanos BETWEEN 0 AND 999),
    updated_at timestamptz NOT NULL,
    document   text        NOT NULL
);

CREATE INDEX IF NOT EXISTS incidents_created_at_idx
    ON aegis.incidents (created_at DESC, created_at_nanos DESC, id);

CREATE INDEX IF NOT EXISTS incidents_status_created_at_idx
    ON aegis.incidents (status, created_at DESC, created_at_nanos DESC, id);
