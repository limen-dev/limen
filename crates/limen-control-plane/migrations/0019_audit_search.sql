-- Searching recent audit events and, if switched on, recording text
-- (ADR-0026). A convenience copy for the console and CLI: the sinks hold the
-- record, and `limen-audit-verify` stays the source of truth. Trimmed after
-- `--search-retention` (30 days by default).

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE audit_search (
    event_id   UUID        PRIMARY KEY,
    at         TIMESTAMPTZ NOT NULL,
    kind       TEXT        NOT NULL,
    username   TEXT,
    session_id UUID,
    resource   TEXT,
    -- `ok` or `denied`.
    outcome    TEXT        NOT NULL DEFAULT 'ok',
    -- What was done, in words: the command or statement, the path, the names
    -- involved. Secret shapes are masked before it lands here.
    text       TEXT        NOT NULL,
    tsv        TSVECTOR    GENERATED ALWAYS AS (to_tsvector('simple', text)) STORED
);
CREATE INDEX audit_search_at ON audit_search (at DESC);
CREATE INDEX audit_search_user ON audit_search (lower(username), at DESC);
CREATE INDEX audit_search_resource ON audit_search (resource, at DESC);
CREATE INDEX audit_search_session ON audit_search (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX audit_search_tsv ON audit_search USING GIN (tsv);
CREATE INDEX audit_search_trgm ON audit_search USING GIN (text gin_trgm_ops);

-- Terminal output of recordings, in chunks with the time each started, only
-- when `--search-recordings` is on. Output only, never input; secret shapes
-- masked; capped per session.
CREATE TABLE recording_text (
    session_id UUID             NOT NULL,
    seq        INTEGER          NOT NULL,
    -- Seconds from the start of the recording.
    t          DOUBLE PRECISION NOT NULL,
    text       TEXT             NOT NULL,
    tsv        TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', text)) STORED,
    PRIMARY KEY (session_id, seq)
);
CREATE INDEX recording_text_tsv ON recording_text USING GIN (tsv);
CREATE INDEX recording_text_trgm ON recording_text USING GIN (text gin_trgm_ops);

CREATE TABLE recording_text_state (
    session_id UUID        PRIMARY KEY,
    bytes      INTEGER     NOT NULL,
    truncated  BOOLEAN     NOT NULL DEFAULT false,
    indexed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
