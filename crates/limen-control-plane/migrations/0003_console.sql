-- Web console state (ADR-0017): who has logged in, sessions as seen in the
-- audit stream, browser login state, and who revoked a component.

CREATE TABLE users (
    username       TEXT        PRIMARY KEY,
    subject        TEXT        NOT NULL,
    roles          TEXT[]      NOT NULL DEFAULT '{}',
    groups         TEXT[]      NOT NULL DEFAULT '{}',
    first_login_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    login_count    BIGINT      NOT NULL DEFAULT 1
);

-- A projection of session.start / session.end / session.recording events,
-- filled by an audit consumer. Rows may be created by any of the three, in
-- any order, and more than once (at-least-once delivery).
CREATE TABLE sessions (
    session_id       UUID        PRIMARY KEY,
    username         TEXT,
    kind             TEXT,
    resource         TEXT,
    login            TEXT,
    worker_id        TEXT,
    proxy_id         TEXT,
    client_addr      TEXT,
    started_at       TIMESTAMPTZ,
    ended_at         TIMESTAMPTZ,
    end_reason       TEXT,
    duration_ms      BIGINT,
    bytes_in         BIGINT,
    bytes_out        BIGINT,
    recording_uri    TEXT,
    recording_sha256 TEXT
);
CREATE INDEX sessions_user ON sessions (username, started_at DESC);
CREATE INDEX sessions_started ON sessions (started_at DESC);
CREATE INDEX sessions_active ON sessions (started_at) WHERE ended_at IS NULL;

-- Browser sessions. The cookie holds a random token; only its hash is stored.
CREATE TABLE console_sessions (
    token_hash BYTEA       PRIMARY KEY,
    username   TEXT        NOT NULL,
    roles      TEXT[]      NOT NULL,
    login_id   TEXT        NOT NULL,
    csrf       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX console_sessions_user ON console_sessions (username);

-- In-flight browser logins (OIDC authorization code with PKCE).
CREATE TABLE console_logins (
    state_hash    BYTEA       PRIMARY KEY,
    nonce         TEXT        NOT NULL,
    pkce_verifier TEXT        NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);

-- `components.revoked_at` already exists; record who revoked.
ALTER TABLE components ADD COLUMN revoked_by TEXT;
