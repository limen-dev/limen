-- Scheduled self-test of the controls (ADR-0053).

-- One row per run. The signed report is kept as the exact bytes that were
-- signed (bytea): jsonb would reorder keys and break the signature.
CREATE TABLE selftest_runs (
    id              UUID        PRIMARY KEY,
    trigger         TEXT        NOT NULL CHECK (trigger IN ('schedule', 'manual')),
    requested_by    TEXT        NOT NULL,
    control_plane   TEXT        NOT NULL,
    status          TEXT        NOT NULL CHECK (status IN ('running', 'passed', 'failed', 'error', 'abandoned')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    passed          INTEGER     NOT NULL DEFAULT 0,
    failed          INTEGER     NOT NULL DEFAULT 0,
    skipped         INTEGER     NOT NULL DEFAULT 0,
    manifest_sha256 TEXT,
    report          BYTEA,
    error           TEXT
);
-- One run at a time across every replica: a second claim conflicts here.
CREATE UNIQUE INDEX selftest_one_running ON selftest_runs ((true)) WHERE status = 'running';
CREATE INDEX selftest_runs_started ON selftest_runs (started_at DESC);
