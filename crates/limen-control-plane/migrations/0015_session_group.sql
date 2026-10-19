-- Sessions opened by one client run (a MongoDB driver opens several
-- connections) share a group, so the console can show them as one.
ALTER TABLE sessions ADD COLUMN conn_group TEXT;
CREATE INDEX sessions_conn_group ON sessions (conn_group) WHERE conn_group IS NOT NULL;
