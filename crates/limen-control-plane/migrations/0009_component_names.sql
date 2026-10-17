-- Optional display names for proxies and workers (Phase 5). The id stays the
-- identity; the name is for people. A join token may approve an exact name
-- or a pattern with one `*`. Names are unique among components that are not
-- revoked, of either kind: revoking a component frees its name. Rows from
-- before this migration have no name.
ALTER TABLE components ADD COLUMN name TEXT;
ALTER TABLE join_tokens ADD COLUMN name TEXT;

CREATE UNIQUE INDEX components_live_name_idx
    ON components (name)
    WHERE name IS NOT NULL AND revoked_at IS NULL;
