-- Machine identities (ADR-0019). Bots are rows in `users` named `bot:<name>`,
-- marked by `actor_type`, with the CI facts of their latest login. Sessions
-- record who the actor was and which CI run it was.
ALTER TABLE users ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN last_ci JSONB;
ALTER TABLE sessions ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'user';
ALTER TABLE sessions ADD COLUMN ci JSONB;
CREATE INDEX sessions_actor ON sessions (actor_type, started_at DESC);
