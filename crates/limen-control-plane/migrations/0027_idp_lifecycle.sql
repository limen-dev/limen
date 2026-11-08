-- IdP-driven offboarding (ADR-0046) and where a user came from.

-- Where the person came from and what the IdP last said about them. Bots keep
-- their own rows (`actor_type = 'bot'`) and are always `source = 'bot'`.
ALTER TABLE users
    ADD COLUMN source         TEXT NOT NULL DEFAULT 'idp_login',
    ADD COLUMN issuer         TEXT,
    -- unchecked: no refresh token, or not checked yet. ok: the IdP vouched at
    -- idp_checked_at. check_failed: the IdP could not be asked. offboarded:
    -- the IdP refused the session and the person was locked.
    ADD COLUMN idp_status     TEXT NOT NULL DEFAULT 'unchecked',
    ADD COLUMN idp_checked_at TIMESTAMPTZ;
UPDATE users SET source = 'bot' WHERE actor_type = 'bot';

-- One row per login that handed over a refresh token. The token is sealed
-- (AES-256-GCM, key from --idp-token-key); it is never returned by any API.
-- Rows are deleted when the login ends, is revoked, or passes expires_at.
CREATE TABLE idp_logins (
    login_id      TEXT        PRIMARY KEY,
    username      TEXT        NOT NULL,
    refresh_token BYTEA       NOT NULL,
    -- The IdP groups the login was issued with, to tell which removals matter.
    groups        TEXT[]      NOT NULL DEFAULT '{}',
    expires_at    TIMESTAMPTZ NOT NULL,
    next_check_at TIMESTAMPTZ NOT NULL,
    last_ok_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idp_logins_due ON idp_logins (next_check_at);
CREATE INDEX idp_logins_user ON idp_logins (lower(username));
