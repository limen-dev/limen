-- Access reviews and deny overrides (ADR-0029). A review takes a snapshot of
-- who holds which role and asks the owners to certify it or flag it. A flag
-- becomes a deny override: carried in the signed snapshot like a lock, it
-- withholds the role from the person while the IdP group is fixed.

CREATE TABLE access_reviews (
    id           UUID        PRIMARY KEY,
    name         TEXT        NOT NULL,
    started_by   TEXT        NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    due_at       TIMESTAMPTZ NOT NULL,
    -- open, complete, or cancelled.
    status       TEXT        NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'complete', 'cancelled')),
    completed_at TIMESTAMPTZ,
    -- Digest of the policy the snapshot was taken against.
    policy_digest TEXT       NOT NULL,
    -- Days a flagged role stays withheld, unless the IdP change is seen first.
    override_days INTEGER    NOT NULL DEFAULT 30
);

CREATE TABLE review_items (
    id            UUID        PRIMARY KEY,
    review_id     UUID        NOT NULL REFERENCES access_reviews (id) ON DELETE CASCADE,
    -- A person or a bot, and the role they hold.
    subject       TEXT        NOT NULL,
    subject_type  TEXT        NOT NULL CHECK (subject_type IN ('user', 'bot')),
    role          TEXT        NOT NULL,
    -- standing (from a group), grant (from an approved request), or break_glass.
    via           TEXT        NOT NULL DEFAULT 'standing',
    -- [{name, kind, principals[]}] the role reaches for them.
    reaches       JSONB       NOT NULL DEFAULT '[]',
    -- What the reviewer needs to judge it.
    sessions_90d  INTEGER     NOT NULL DEFAULT 0,
    last_used_at  TIMESTAMPTZ,
    -- Who decides: a user name, or `*admin` for any admin who is not the subject.
    reviewer      TEXT        NOT NULL,
    decision      TEXT        CHECK (decision IN ('certify', 'flag')),
    comment       TEXT        NOT NULL DEFAULT '',
    decided_by    TEXT,
    decided_at    TIMESTAMPTZ,
    reminded_at   TIMESTAMPTZ,
    escalated_at  TIMESTAMPTZ
);
CREATE INDEX review_items_review ON review_items (review_id);
CREATE INDEX review_items_reviewer ON review_items (reviewer) WHERE decision IS NULL;

CREATE TABLE access_denies (
    id             UUID        PRIMARY KEY,
    username       TEXT        NOT NULL,
    role           TEXT        NOT NULL,
    reason         TEXT        NOT NULL,
    created_by     TEXT        NOT NULL,
    review_item_id UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    lifted_at      TIMESTAMPTZ,
    lifted_by      TEXT,
    lift_reason    TEXT
);
CREATE INDEX access_denies_active ON access_denies (username) WHERE lifted_at IS NULL;
-- One live override per person and role.
CREATE UNIQUE INDEX access_denies_one ON access_denies (username, role) WHERE lifted_at IS NULL;
