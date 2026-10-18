-- The Kubernetes requests behind `kube.request` audit events, for the
-- console's Kubernetes view (ADR-0033). Like `audit_events` this is a
-- convenience copy, not the audit record: only the request's shape is kept
-- (verb, resource, namespace, name, status), never a body, a query string, or
-- a header; a path is kept only when there is no resource to name. Trimmed after 30 days.
CREATE TABLE kube_requests (
    event_id    UUID        PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL,
    username    TEXT,
    session_id  UUID,
    cluster     TEXT        NOT NULL,
    verb        TEXT        NOT NULL,
    api_group   TEXT        NOT NULL DEFAULT '',
    resource    TEXT        NOT NULL DEFAULT '',
    subresource TEXT        NOT NULL DEFAULT '',
    namespace   TEXT        NOT NULL DEFAULT '',
    name        TEXT        NOT NULL DEFAULT '',
    -- The path, only for requests that name no resource (/version, /healthz).
    path        TEXT        NOT NULL DEFAULT '',
    method      TEXT        NOT NULL DEFAULT '',
    status      INTEGER     NOT NULL,
    latency_ms  BIGINT,
    error       TEXT
);
CREATE INDEX kube_requests_at ON kube_requests (at DESC);
CREATE INDEX kube_requests_user ON kube_requests (username, at DESC);
CREATE INDEX kube_requests_cluster ON kube_requests (cluster, at DESC);
