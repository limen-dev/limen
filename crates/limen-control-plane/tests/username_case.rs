//! Usernames that differ only in case are one person for locks and for
//! two-person approval. Set `LIMEN_TEST_DATABASE_URL` to run them.

#![allow(clippy::large_futures)]

mod common;

use common::Harness;
use limen_control_plane::access::store;
use limen_control_plane::db;
use uuid::Uuid;

#[tokio::test]
async fn a_lock_covers_every_spelling_of_the_username() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pool = &h.state.db;
    assert!(
        db::lock_user(pool, "Alice@Example.com", "r", "root")
            .await
            .expect("lock")
    );
    assert!(db::is_locked(pool, "alice@example.com").await.expect("q"));
    assert!(
        db::lock_and_logout(pool, "ALICE@example.com", "none")
            .await
            .expect("q")
            .0
    );
    assert!(
        !db::lock_user(pool, "alice@example.com", "again", "root")
            .await
            .expect("lock"),
        "a second spelling is the same lock"
    );
    assert!(
        db::unlock_user(pool, "ALICE@EXAMPLE.COM", "root")
            .await
            .expect("unlock")
    );
    assert!(!db::is_locked(pool, "Alice@Example.com").await.expect("q"));
}

#[tokio::test]
async fn one_person_approves_once_whatever_the_case() {
    let Some(h) = Harness::start().await else {
        return;
    };
    let pool = &h.state.db;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO access_requests (id, requester, role, resource, duration_secs, status, approvals_required, expires_at)
         VALUES ($1, 'dev@example.com', 'r', 'res', 60, 'pending', 2, now() + interval '1 hour')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("request");
    let mut tx = pool.begin().await.expect("tx");
    assert!(
        store::insert_approval(&mut tx, id, "Lead@Example.com", "approve", "")
            .await
            .expect("first")
    );
    assert!(
        !store::insert_approval(&mut tx, id, "lead@example.com", "approve", "")
            .await
            .expect("second"),
        "the same person in another case is not a second approver"
    );
}
