-- The approval queue.
--
-- The `request` column holds the request as JSON text, as the dispatcher submitted it.
-- The decision columns hold the decision. A request gets one decision, and the decision
-- does not change. A trigger enforces this rule for each client.

CREATE TABLE IF NOT EXISTS aegis.approvals (
    id           uuid        PRIMARY KEY,
    status       text        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    -- The request time, rounded down to microseconds.
    requested_at timestamptz NOT NULL,
    -- The nanoseconds of the request time that `requested_at` cannot keep.
    requested_at_nanos smallint NOT NULL CHECK (requested_at_nanos BETWEEN 0 AND 999),
    decided_by   text,
    decided_at   timestamptz,
    note         text,
    request      text        NOT NULL,
    CHECK ((status = 'pending') = (decided_by IS NULL)),
    CHECK ((status = 'pending') = (decided_at IS NULL)),
    CHECK (status <> 'pending' OR note IS NULL)
);

CREATE INDEX IF NOT EXISTS approvals_pending_idx
    ON aegis.approvals (requested_at, requested_at_nanos, id)
    WHERE status = 'pending';

CREATE OR REPLACE FUNCTION aegis.approvals_guard_decision()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $guard$
BEGIN
    IF OLD.status <> 'pending' THEN
        RAISE EXCEPTION 'approval request % already has a decision', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status = 'pending' THEN
        RAISE EXCEPTION 'an update of approval request % must record a decision', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.request IS DISTINCT FROM OLD.request
        OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
        OR NEW.requested_at_nanos IS DISTINCT FROM OLD.requested_at_nanos THEN
        RAISE EXCEPTION 'the request data of approval request % cannot change', OLD.id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$guard$;

DROP TRIGGER IF EXISTS approvals_guard ON aegis.approvals;
CREATE TRIGGER approvals_guard
    BEFORE UPDATE ON aegis.approvals
    FOR EACH ROW
    EXECUTE FUNCTION aegis.approvals_guard_decision();
