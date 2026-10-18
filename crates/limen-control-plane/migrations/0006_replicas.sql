-- Control plane replica registry (Phase 5). A replica inserts its row at
-- start and heartbeats; a live row with the same id refuses a second start.
-- Also gives peer discovery for spool handoff.
CREATE TABLE control_plane_replicas (
    id           TEXT PRIMARY KEY,
    ingest_url   TEXT NOT NULL,
    spool_mode   TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
