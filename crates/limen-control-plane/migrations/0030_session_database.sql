-- The database a SQL or MongoDB session used, from `session.start`, so a
-- policy change can be replayed against recorded sessions (ADR-0050). Rows
-- from before this migration stay NULL and are reported as not replayable.
ALTER TABLE sessions ADD COLUMN database TEXT;
