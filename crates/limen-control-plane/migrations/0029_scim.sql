-- SCIM 2.0 provisioning (ADR-0048).

-- A person provisioned by the IdP has no subject until they first sign in.
ALTER TABLE users ALTER COLUMN subject DROP NOT NULL;
-- Everyone has an id from the start (a volatile default is evaluated per row),
-- so SCIM never has to number people on a read.
ALTER TABLE users ADD COLUMN scim_id UUID NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX users_scim_id ON users (scim_id);

-- Groups the IdP pushes, and who is in them. Members are SCIM user ids.
CREATE TABLE scim_groups (
    id           UUID        PRIMARY KEY,
    display_name TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scim_groups_name ON scim_groups (lower(display_name));

CREATE TABLE scim_group_members (
    group_id     UUID NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
    user_scim_id UUID NOT NULL,
    PRIMARY KEY (group_id, user_scim_id)
);
CREATE INDEX scim_group_members_user ON scim_group_members (user_scim_id);
