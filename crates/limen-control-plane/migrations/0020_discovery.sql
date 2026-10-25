-- Discovered resources (ADR-0027). Workers report what they see in a cloud
-- account; the control plane names it and labels it from the `discovery`
-- document, and holds anything new, or any changed label, until an admin
-- accepts it. Only accepted rows become resources policy can select.

CREATE TABLE discovered_resources (
    -- aws:<account>:<region>:<source>:<id>. Stable while the thing exists.
    key            TEXT        PRIMARY KEY,
    document       TEXT        NOT NULL,
    matcher        INTEGER     NOT NULL,
    source         TEXT        NOT NULL,
    account        TEXT        NOT NULL,
    region         TEXT        NOT NULL,
    provider_id    TEXT        NOT NULL,
    -- What the worker reported, and the proposal the document made of it.
    found          JSONB       NOT NULL,
    proposal       JSONB       NOT NULL,
    -- pending: never accepted. accepted: in force. rejected: an admin said
    -- no. stale: not seen for several scans; refused until it is seen again.
    state          TEXT        NOT NULL
        CHECK (state IN ('pending', 'accepted', 'rejected', 'stale')),
    -- The resource as accepted ({name, labels, spec}). A later change to the
    -- proposal waits in `change_pending` while this stays in force.
    accepted       JSONB,
    accepted_by    TEXT,
    accepted_at    TIMESTAMPTZ,
    change_pending BOOLEAN     NOT NULL DEFAULT false,
    -- Digest of the proposal a pending change was announced for, so a
    -- repeated report doesn't repeat the event.
    announced      TEXT,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    missed_cycles  INTEGER     NOT NULL DEFAULT 0,
    stale_since    TIMESTAMPTZ,
    reported_by    TEXT        NOT NULL,
    reviewed_by    TEXT,
    reviewed_at    TIMESTAMPTZ,
    review_note    TEXT
);
CREATE INDEX discovered_state ON discovered_resources (state);
CREATE INDEX discovered_scope ON discovered_resources (document, matcher, account, region);
