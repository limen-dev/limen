-- Policy writes held for approval because they widen standing access
-- (ADR-0042 §6). `plan` is the write as the control plane will apply it;
-- `writes` the request as sent, for approvers to read. A change is decided
-- once: `applying` marks one being approved, so two approvers can't both
-- apply it (a claim older than a few minutes is from a crashed replica and
-- may be taken again).

CREATE TABLE policy_changes (
    id                   UUID        PRIMARY KEY,
    state                TEXT        NOT NULL CHECK (state IN
                             ('pending', 'applying', 'applied', 'rejected', 'cancelled', 'expired', 'superseded')),
    author               TEXT        NOT NULL,
    author_ci            JSONB       NOT NULL DEFAULT '{}',
    plan                 JSONB       NOT NULL,
    writes               BYTEA       NOT NULL,
    impact               BYTEA       NOT NULL,
    base_policy_version  BIGINT      NOT NULL,
    reason               TEXT        NOT NULL DEFAULT '',
    source_ref           TEXT        NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ NOT NULL,
    claimed_at           TIMESTAMPTZ,
    decided_by           TEXT,
    decision_note        TEXT,
    decided_at           TIMESTAMPTZ,
    applied_policy_version BIGINT
);
CREATE INDEX policy_changes_state ON policy_changes (state, created_at DESC);
CREATE INDEX policy_changes_author ON policy_changes (author, created_at DESC);
