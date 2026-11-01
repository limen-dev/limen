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
CREATE INDEX policy_manifest_document ON policy_manifest (document_digest);

ALTER TABLE policy_versions ALTER COLUMN documents DROP NOT NULL;
