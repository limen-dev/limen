-- Ownership token for a registry row: a random per-process nonce, so a
-- stalled replica whose id was taken over can't refresh or delete the new
-- owner's row.
ALTER TABLE control_plane_replicas ADD COLUMN owner_nonce TEXT NOT NULL DEFAULT '';
