-- Public identity-assertion signing keys shared by all control-plane replicas.
ALTER TABLE web_app_logins
    ADD COLUMN IF NOT EXISTS browser_nonce_hash BYTEA;
ALTER TABLE web_app_handoffs
    ADD COLUMN IF NOT EXISTS browser_nonce_hash BYTEA;
-- In-flight browser logins are short-lived and cannot be safely rebound.
DELETE FROM web_app_logins;
DELETE FROM web_app_handoffs;
ALTER TABLE web_app_logins
    ALTER COLUMN browser_nonce_hash SET NOT NULL;
ALTER TABLE web_app_handoffs
    ALTER COLUMN browser_nonce_hash SET NOT NULL;

CREATE TABLE web_identity_jwks (
    kid       TEXT        PRIMARY KEY,
    jwk       JSONB       NOT NULL,
    not_after TIMESTAMPTZ NOT NULL
);
CREATE INDEX web_identity_jwks_not_after_idx ON web_identity_jwks (not_after);
