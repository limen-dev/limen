-- Statements of SQL database sessions (Phase 6, ADR-0033), for the console's
-- session page. A projection of the `db.query` and `db.query.end` audit
-- events, like `sessions`: idempotent and order-independent, every column set
-- by exactly one kind of event. The full trail stays in the audit sinks; the
-- text kept here is cut at 16 KiB. Only admins and the session's own user can
-- open the page that reads it.
CREATE TABLE db_statements (
    event_id       UUID PRIMARY KEY,           -- the db.query event; db.query.end names it
    session_id     UUID NOT NULL,
    at             TIMESTAMPTZ NOT NULL,
    phase          TEXT,
    statement_type TEXT,
    statement      TEXT,
    truncated      BOOLEAN NOT NULL DEFAULT FALSE,
    status         TEXT,
    "rows"         BIGINT,
    duration_ms    BIGINT,
    error_code     TEXT,
    error          TEXT
);

CREATE INDEX db_statements_session_idx ON db_statements (session_id, at);
