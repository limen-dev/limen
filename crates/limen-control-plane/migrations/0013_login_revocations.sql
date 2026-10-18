-- Logins ended by `limen logout` (ADR-0038). A user certificate carries its
-- login id, so this ends one login without touching the user's others. Proxies
-- and workers learn of it through the signed policy snapshot, like session
-- kills. Kept two days, longer than any certificate lives.
CREATE TABLE login_revocations (
    login_id   TEXT        PRIMARY KEY,
    username   TEXT        NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Console sessions made from a login (kubectl sessions), so ending the login
-- ends them.
ALTER TABLE sessions ADD COLUMN login_id TEXT;
CREATE INDEX sessions_login ON sessions (login_id) WHERE login_id IS NOT NULL;
