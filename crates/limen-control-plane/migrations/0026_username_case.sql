-- Usernames compare case-insensitively everywhere the application decides
-- (locks, separation of duties); make the database agree, so "Alice" and
-- "alice" are one person for a lock and for a two-person approval.

-- Collapse case-variant duplicates first, or the new indexes cannot be built.
UPDATE user_locks l
   SET released_at = now(), released_by = 'migration 0026'
 WHERE l.released_at IS NULL
   AND EXISTS (
       SELECT 1 FROM user_locks o
        WHERE o.released_at IS NULL AND lower(o.username) = lower(l.username)
          AND (o.locked_at, o.id) < (l.locked_at, l.id));

DROP INDEX user_locks_active;
CREATE UNIQUE INDEX user_locks_active ON user_locks (lower(username)) WHERE released_at IS NULL;

DELETE FROM access_approvals a
 WHERE EXISTS (
       SELECT 1 FROM access_approvals o
        WHERE o.request_id = a.request_id AND lower(o.approver) = lower(a.approver)
          AND (o.decided_at, o.approver) < (a.decided_at, a.approver));

CREATE UNIQUE INDEX access_approvals_one_per_person
    ON access_approvals (request_id, lower(approver));
