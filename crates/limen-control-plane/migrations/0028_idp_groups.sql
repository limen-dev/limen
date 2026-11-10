-- The groups the IdP last reported for a person at an IdP check (ADR-0047),
-- so the console can show access they have gained or lost since they last
-- signed in. NULL: not reported (no check yet, or the token had no groups
-- claim). `users.groups` and `users.roles` stay as of the last sign-in.
ALTER TABLE users
    ADD COLUMN idp_groups    TEXT[],
    ADD COLUMN idp_groups_at TIMESTAMPTZ;
