-- One-use OIDC state and handoffs for host-isolated web app sessions (ADR-0022).

CREATE TABLE web_app_logins (
    state_hash    BYTEA       PRIMARY KEY,
    resource      TEXT        NOT NULL,
    host          TEXT        NOT NULL,
    return_path   TEXT        NOT NULL,
    nonce         TEXT        NOT NULL,
    pkce_verifier TEXT        NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE web_app_handoffs (
    token_hash   BYTEA       PRIMARY KEY,
    resource     TEXT        NOT NULL,
    host         TEXT        NOT NULL,
    return_path  TEXT        NOT NULL,
    session      BYTEA       NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);

-- The session view keeps the audited shape of each web request, never a body,
-- query string, cookie, or authorization header.
CREATE TABLE web_requests (
    request_id        UUID        PRIMARY KEY,
    request_event_id  UUID        NOT NULL UNIQUE,
    response_event_id UUID        UNIQUE,
    at                TIMESTAMPTZ NOT NULL,
    username          TEXT        NOT NULL,
    resource          TEXT        NOT NULL,
    host              TEXT        NOT NULL,
    method            TEXT        NOT NULL,
    path              TEXT        NOT NULL,
    status            INTEGER,
    bytes_in          BIGINT,
    bytes_out         BIGINT,
    duration_ms       BIGINT,
    outcome           TEXT
);
CREATE INDEX web_requests_session_idx ON web_requests (username, at DESC);
