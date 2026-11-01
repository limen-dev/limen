-- One owner per policy document (ADR-0042 §3). A head is the current
-- revision of one document: who manages it, what they wrote, and its etag.
-- policy_versions keeps the full, signed document set of every version;
-- heads say how that set was made, so writers only replace their own part.
--
-- `input` is the document as its owner wrote it. For a resource a bot writer
-- completed from a profile, it is only the writer's half (name, labels, the
-- settable fields), and `profile` names the profile that fills in the rest.

CREATE TABLE policy_document_heads (
    kind           TEXT        NOT NULL,
    name           TEXT        NOT NULL,
    channel        TEXT        NOT NULL CHECK (channel IN ('git', 'console', 'api')),
    source         TEXT        NOT NULL,
    namespace      TEXT        NOT NULL,
    input          JSONB       NOT NULL,
    profile        TEXT,
    etag           TEXT        NOT NULL,
    policy_version BIGINT      NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by     TEXT        NOT NULL,
    PRIMARY KEY (kind, name)
);
CREATE INDEX policy_document_heads_owner ON policy_document_heads (namespace, source);

-- Results of writes made with a request_id, so a retry returns the first
-- result instead of writing again (ADR-0042 §1). Kept for 24 hours.
CREATE TABLE policy_requests (
    principal  TEXT        NOT NULL,
    request_id TEXT        NOT NULL,
    body_hash  TEXT        NOT NULL,
    response   BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal, request_id)
);
CREATE INDEX policy_requests_created ON policy_requests (created_at);

-- Everything applied so far was applied from files: it belongs to the
-- default source. md5 etags are opaque like the ones the control plane
-- computes from here on.
INSERT INTO policy_document_heads
    (kind, name, channel, source, namespace, input, etag, policy_version, updated_by)
SELECT d->>'kind', d->'metadata'->>'name', 'git', 'default', 'default', d,
       md5(d::text), latest.version, latest.author
FROM (SELECT version, author, documents FROM policy_versions ORDER BY version DESC LIMIT 1) AS latest,
     jsonb_array_elements(latest.documents) AS d;
