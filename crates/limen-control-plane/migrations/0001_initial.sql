-- Limen control plane state (ADR-0010). No secret material is stored here:
-- join tokens and login nonces are stored as SHA-256 hashes, and CA private
-- keys live in KMS (or on disk in development).

CREATE TABLE ca_certs (
    purpose     TEXT        NOT NULL,
    key_ref     TEXT        NOT NULL,
    cert_pem    TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (purpose, key_ref)
);

CREATE TABLE policy_versions (
    version     BIGSERIAL   PRIMARY KEY,
    digest      TEXT        NOT NULL,
    documents   JSONB       NOT NULL,
    author      TEXT        NOT NULL,
    source_ref  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE join_tokens (
    token_hash  BYTEA       PRIMARY KEY,
    kind        TEXT        NOT NULL CHECK (kind IN ('proxy', 'worker')),
    labels      JSONB       NOT NULL DEFAULT '{}',
    dns_names   TEXT[]      NOT NULL DEFAULT '{}',
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    used_by     TEXT
);

CREATE TABLE components (
    id              TEXT        PRIMARY KEY,
    kind            TEXT        NOT NULL CHECK (kind IN ('proxy', 'worker')),
    labels          JSONB       NOT NULL DEFAULT '{}',
    dns_names       TEXT[]      NOT NULL DEFAULT '{}',
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    cert_expires_at TIMESTAMPTZ,
    peer_address    TEXT,
    revoked_at      TIMESTAMPTZ
);

CREATE TABLE tunnels (
    proxy_id         TEXT        NOT NULL REFERENCES components (id),
    tunnel_id        TEXT        NOT NULL,
    worker_id        TEXT        NOT NULL REFERENCES components (id),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (proxy_id, tunnel_id)
);
CREATE INDEX tunnels_worker_idx ON tunnels (worker_id);

-- Single-use record of ID tokens already exchanged for credentials.
CREATE TABLE login_nonces (
    nonce_hash  BYTEA       PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL
);
