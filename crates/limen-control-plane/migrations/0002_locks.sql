-- Locks and session kills (ADR-0017). Proxies and workers learn of both
-- through the signed policy snapshot, which the control plane builds from
-- these tables on every request.

CREATE TABLE user_locks (
    id          UUID        PRIMARY KEY,
    username    TEXT        NOT NULL,
    reason      TEXT        NOT NULL,
    locked_by   TEXT        NOT NULL,
    locked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by TEXT,
    released_at TIMESTAMPTZ
);
-- At most one active lock per user.
CREATE UNIQUE INDEX user_locks_active ON user_locks (username) WHERE released_at IS NULL;

CREATE TABLE session_kills (
    session_id  TEXT        PRIMARY KEY,
    reason      TEXT        NOT NULL,
    killed_by   TEXT        NOT NULL,
    killed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
