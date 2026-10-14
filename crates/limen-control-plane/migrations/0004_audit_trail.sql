-- A short, searchable trail of audit events for the console (ADR-0017). This
-- is a convenience copy, not the audit record: the sinks hold the complete,
-- signed events. Only a fixed set of fields is kept, in `summary`, so
-- statement text and other payloads never land here. Trimmed after 30 days.
CREATE TABLE audit_events (
    event_id   UUID        PRIMARY KEY,
    at         TIMESTAMPTZ NOT NULL,
    kind       TEXT        NOT NULL,
    username   TEXT,
    session_id UUID,
    summary    TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX audit_events_at ON audit_events (at DESC);
CREATE INDEX audit_events_user ON audit_events (username, at DESC);
CREATE INDEX audit_events_kind ON audit_events (kind, at DESC);
