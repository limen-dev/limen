-- Pinned resources and saved views for the web console (ADR-0055).
--
-- A person's own preferences, read and written only for their own user name. No secrets and no
-- policy: `target` is a resource name, or a console address (path and query) that the page it
-- names checks access for when it is opened. Capped per person by the application.
CREATE TABLE console_pins (
    username   TEXT        NOT NULL,
    kind       TEXT        NOT NULL CHECK (kind IN ('resource', 'view')),
    target     TEXT        NOT NULL,
    label      TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (username, kind, target)
);
