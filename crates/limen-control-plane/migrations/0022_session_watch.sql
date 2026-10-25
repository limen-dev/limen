-- Watching a live session (ADR-0030). A watcher row says someone is looking
-- right now; chunks are the recent terminal output the worker published for
-- them. Both are short-lived: chunks go after two minutes, and a watcher
-- whose browser stops asking is not a watcher after twenty seconds.

CREATE TABLE session_watches (
    id           UUID        PRIMARY KEY,
    session_id   UUID        NOT NULL,
    observer     TEXT        NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    stopped_at   TIMESTAMPTZ
);
CREATE INDEX session_watches_live ON session_watches (session_id, last_seen_at) WHERE stopped_at IS NULL;

CREATE TABLE watch_chunks (
    session_id UUID             NOT NULL,
    seq        BIGSERIAL,
    at         TIMESTAMPTZ      NOT NULL DEFAULT now(),
    elapsed_ms BIGINT           NOT NULL,
    cols       INTEGER          NOT NULL DEFAULT 80,
    rows       INTEGER          NOT NULL DEFAULT 24,
    text       TEXT             NOT NULL,
    PRIMARY KEY (session_id, seq)
);
CREATE INDEX watch_chunks_at ON watch_chunks (at);
