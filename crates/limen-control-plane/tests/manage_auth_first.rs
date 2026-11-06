//! The read-only management calls authenticate before they touch the
//! policy store. Set `LIMEN_TEST_DATABASE_URL` to run them.

#![allow(clippy::large_futures)]

mod common;

use common::Harness;
use limen_control_plane::services::manage::ManageService;
use limen_proto::manage::v1::management_service_server::ManagementService as _;
use limen_proto::manage::v1::{DescribeCallerRequest, GetDocumentRequest, ListDocumentsRequest};
use tonic::{Code, Request};

fn anonymous<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(limen_tunnel::PeerInfo {
        remote_addr: None,
        server_name: None,
        client_certs: Vec::new(),
    });
    request
}

#[tokio::test]
async fn an_unauthenticated_caller_causes_no_policy_store_work() {
    let Some(h) = Harness::start().await else {
        return;
    };
    // With the pool closed, any database work fails with a store error; an
    // unauthenticated request must be refused before it gets that far.
    let state = h.state.clone();
    state.db.close().await;
    let svc = ManageService(state);
    let code = svc
        .describe_caller(anonymous(DescribeCallerRequest {}))
        .await
        .expect_err("no certificate")
        .code();
    assert_eq!(code, Code::Unauthenticated);
    let code = svc
        .get_document(anonymous(GetDocumentRequest::default()))
        .await
        .expect_err("no certificate")
        .code();
    assert_eq!(code, Code::Unauthenticated);
    let code = svc
        .list_documents(anonymous(ListDocumentsRequest::default()))
        .await
        .expect_err("no certificate")
        .code();
    assert_eq!(code, Code::Unauthenticated);
}
