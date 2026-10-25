-- Just-in-time access (ADR-0025): requests, the approvals they collect, and
-- the time-boxed grants they become. Proxies and workers learn of active
-- grants through the signed policy snapshot, like locks.

CREATE TABLE access_requests (
    id                 UUID        PRIMARY KEY,
    requester          TEXT        NOT NULL,
    role               TEXT        NOT NULL,
    resource           TEXT        NOT NULL,
    reason             TEXT        NOT NULL DEFAULT '',
    duration_secs      INTEGER     NOT NULL CHECK (duration_secs > 0),
    status             TEXT        NOT NULL
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled', 'revoked')),
    break_glass        BOOLEAN     NOT NULL DEFAULT false,
    approvals_required INTEGER     NOT NULL DEFAULT 1 CHECK (approvals_required BETWEEN 1 AND 5),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A pending request lapses at this time.
    expires_at         TIMESTAMPTZ NOT NULL,
    decided_at         TIMESTAMPTZ
);
CREATE INDEX access_requests_requester ON access_requests (requester, created_at DESC);
CREATE INDEX access_requests_created ON access_requests (created_at DESC);
CREATE INDEX access_requests_pending ON access_requests (expires_at) WHERE status = 'pending';
-- One open request per person, role, and resource: asking twice doesn't
-- double the approvers' queue.
CREATE UNIQUE INDEX access_requests_one_open
    ON access_requests (requester, role, resource) WHERE status = 'pending';

CREATE TABLE access_approvals (
    request_id UUID        NOT NULL REFERENCES access_requests (id) ON DELETE CASCADE,
    approver   TEXT        NOT NULL,
    decision   TEXT        NOT NULL CHECK (decision IN ('approve', 'deny')),
    comment    TEXT        NOT NULL DEFAULT '',
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A second approval has to come from a different person.
    PRIMARY KEY (request_id, approver)
);

-- The last line of defence for separation of duties: whatever code path
-- writes an approval, the requester can't be the approver.
CREATE FUNCTION access_no_self_approval() RETURNS trigger AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM access_requests r
        WHERE r.id = NEW.request_id AND lower(r.requester) = lower(NEW.approver)
    ) THEN
        RAISE EXCEPTION 'a request cannot be decided by its requester'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER access_approvals_no_self
    BEFORE INSERT ON access_approvals
    FOR EACH ROW EXECUTE FUNCTION access_no_self_approval();

-- One grant per approved (or break-glass) request. The request id is the
-- grant's id everywhere.
CREATE TABLE access_grants (
    request_id       UUID        PRIMARY KEY REFERENCES access_requests (id),
    username         TEXT        NOT NULL,
    role             TEXT        NOT NULL,
    resource         TEXT        NOT NULL,
    reason           TEXT        NOT NULL DEFAULT '',
    break_glass      BOOLEAN     NOT NULL DEFAULT false,
    approvers        TEXT[]      NOT NULL DEFAULT '{}',
    granted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ,
    revoked_by       TEXT,
    revoke_reason    TEXT,
    -- Set once the `access.expire` event has been written.
    expiry_noted_at  TIMESTAMPTZ
);
CREATE INDEX access_grants_active ON access_grants (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX access_grants_user ON access_grants (username, granted_at DESC);

-- Sessions started under a grant name it, so a revoked grant ends them and
-- the console can show why they were allowed.
ALTER TABLE sessions ADD COLUMN request_ids TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX sessions_request_ids ON sessions USING GIN (request_ids);
