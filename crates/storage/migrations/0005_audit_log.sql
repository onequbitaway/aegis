-- The hash-chained audit log.
--
-- The table is append-only. The application role needs only INSERT and SELECT on it.
-- Triggers reject UPDATE, DELETE, and TRUNCATE, and reject a record that does not
-- continue the chain. The hash chain finds a change that goes around the triggers.

CREATE TABLE IF NOT EXISTS aegis.audit_log (
    sequence    bigint      PRIMARY KEY CHECK (sequence >= 1),
    id          uuid        NOT NULL UNIQUE,
    -- The time of the record. The type keeps microseconds.
    recorded_at timestamptz NOT NULL,
    kind        text        NOT NULL,
    actor       text        NOT NULL,
    summary     text        NOT NULL,
    -- The payload and the evidence as JSON text. Text keeps each number byte for byte.
    payload     text        NOT NULL,
    evidence    text        NOT NULL,
    prev_hash   text        NOT NULL UNIQUE CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash        text        NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE OR REPLACE FUNCTION aegis.audit_log_reject_change()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $reject$
BEGIN
    RAISE EXCEPTION 'the audit log is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'integrity_constraint_violation';
END
$reject$;

DROP TRIGGER IF EXISTS audit_log_append_only ON aegis.audit_log;
CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON aegis.audit_log
    FOR EACH STATEMENT
    EXECUTE FUNCTION aegis.audit_log_reject_change();

CREATE OR REPLACE FUNCTION aegis.audit_log_check_chain()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $chain$
DECLARE
    last_sequence bigint;
    last_hash text;
BEGIN
    SELECT sequence, hash
    INTO last_sequence, last_hash
    FROM aegis.audit_log
    ORDER BY sequence DESC
    LIMIT 1;

    IF NOT FOUND THEN
        last_sequence := 0;
        last_hash := repeat('0', 64);
    END IF;

    IF NEW.sequence IS DISTINCT FROM last_sequence + 1
        OR NEW.prev_hash IS DISTINCT FROM last_hash THEN
        RAISE EXCEPTION 'the audit record does not continue the chain after sequence %', last_sequence
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN NEW;
END
$chain$;

DROP TRIGGER IF EXISTS audit_log_chain ON aegis.audit_log;
CREATE TRIGGER audit_log_chain
    BEFORE INSERT ON aegis.audit_log
    FOR EACH ROW
    EXECUTE FUNCTION aegis.audit_log_check_chain();
