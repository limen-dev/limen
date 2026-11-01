-- Policy document bodies stored once, by digest (#183, ADR-0042 §8).
-- A version no longer repeats every document: it lists which ones in
-- policy_manifest, so a one-document change stores one new body. Versions
-- written before this keep their inline `documents` and stay readable.

CREATE TABLE policy_documents (
    digest TEXT  PRIMARY KEY,
    body   JSONB NOT NULL
);

CREATE TABLE policy_manifest (
    version         BIGINT NOT NULL REFERENCES policy_versions (version),
    position        INT    NOT NULL,
    document_digest TEXT   NOT NULL REFERENCES policy_documents (digest),
    PRIMARY KEY (version, position)
);

-- A version written since this migration has no inline `documents`; it has
-- `document_count` manifest rows instead, which a reader checks, so a
-- version whose manifest is missing or short (a partial restore) is refused
-- and the replica keeps the policy it has instead of loading a partial one.
--
-- UPGRADE ORDER: a replica from before this migration reads `documents` and
-- cannot decode a version without it. Its refresh then fails and it keeps
-- serving the policy it had, until it is upgraded. Upgrade every control
-- plane replica before the first policy write through a new one, and do not
-- roll the binary back after one.
ALTER TABLE policy_versions ALTER COLUMN documents DROP NOT NULL;
ALTER TABLE policy_versions ADD COLUMN document_count INT;
