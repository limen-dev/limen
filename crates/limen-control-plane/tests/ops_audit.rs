//! Admin actions against a failing audit sink. Set `LIMEN_TEST_DATABASE_URL` to run them.

#![allow(clippy::large_futures)]

mod common;

use std::sync::Arc;

use common::Harness;
use limen_audit::{Emitter, FailureMode, MemorySink};
use limen_control_plane::db;
use limen_control_plane::services::ops::{self, Actor};
use limen_testkit::users::{ADMIN, DEVELOPER};
use tonic::Code;

const ACTOR: Actor<'static> = Actor {
    username: ADMIN,
    via: "api",
};

#[tokio::test]
async fn unlock_does_not_stand_when_the_audit_event_cannot_be_written() {
    let Some(h) = Harness::start().await else {
        return;
    };
    ops::lock_user(&h.state, ACTOR, DEVELOPER, "test")
        .await
        .expect("lock");
    let sink = Arc::new(MemorySink::default());
    sink.set_failing(true);
    let mut broken = h.state.clone();
    broken.audit = Emitter::new("control-plane", "t", sink.clone(), FailureMode::FailClosed);

    let err = ops::unlock_user(&broken, ACTOR, DEVELOPER)
        .await
        .expect_err("audit is down");
    assert_eq!(err.code(), Code::Unavailable);
    assert!(
        db::is_locked(&h.state.db, DEVELOPER).await.expect("query"),
        "the user must stay locked"
    );

    // With audit back, the same call works and is recorded.
    sink.set_failing(false);
    assert!(
        ops::unlock_user(&broken, ACTOR, DEVELOPER)
            .await
            .expect("unlock")
    );
    assert!(!db::is_locked(&h.state.db, DEVELOPER).await.expect("query"));
    assert_eq!(sink.events().len(), 1);
}
