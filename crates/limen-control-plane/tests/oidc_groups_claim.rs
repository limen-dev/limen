//! The groups claim is configurable (Cognito names it `cognito:groups`).
//! No database needed: a mock IdP signs tokens, the verifier reads them.

use limen_control_plane::config::UsernameClaim;
use limen_control_plane::http_client::HttpClient;
use limen_control_plane::oidc::OidcVerifier;
use limen_testkit::idp::{Claims, MockIdp};

const CLIENT: &str = "limen-cli";

fn verifier(idp: &MockIdp, claim: Option<&str>) -> OidcVerifier {
    OidcVerifier::new(
        &idp.issuer,
        None,
        CLIENT,
        UsernameClaim::Email,
        claim.unwrap_or("groups"),
        HttpClient::new().expect("http"),
    )
    .expect("verifier")
}

#[tokio::test]
async fn a_cognito_style_groups_claim_gives_roles() {
    let idp = MockIdp::start(CLIENT).await;
    let claims = Claims::user("ada@example.com", &["devs", "sre"]);
    let token = idp.id_token_with_groups_claim(&claims, "cognito:groups");

    let got = verifier(&idp, Some("cognito:groups"))
        .verify(token.clone(), None)
        .await
        .expect("verify");
    assert_eq!(got.groups, ["devs", "sre"]);

    // The default claim name doesn't see them: no silent fallback.
    let got = verifier(&idp, None)
        .verify(token, None)
        .await
        .expect("verify");
    assert!(!got.groups_reported);
    assert_eq!(got.groups, Vec::<String>::new());
}

#[tokio::test]
async fn the_default_claim_is_still_groups() {
    let idp = MockIdp::start(CLIENT).await;
    let token = idp.id_token(&Claims::user("ada@example.com", &["devs"]));
    let got = verifier(&idp, None)
        .verify(token, None)
        .await
        .expect("verify");
    assert_eq!(got.groups, ["devs"]);
}
