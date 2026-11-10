//! SCIM 2.0 through the proxy's public port (ADR-0048): the path Okta's
//! provisioning agent takes, with a real TLS connection, the proxy relay and
//! the control plane's merged router. Unverified against Okta (#64).

use limen_e2e::Deployment;

fn client(d: &Deployment, http1_only: bool) -> reqwest::Client {
    let ca = std::fs::read(d.ca_file()).expect("ca");
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).expect("cert"))
        .resolve("localhost", d.proxy_addr)
        .redirect(reqwest::redirect::Policy::none());
    if http1_only {
        builder = builder.http1_only();
    }
    builder.build().expect("client")
}

#[tokio::test]
async fn okta_reaches_scim_through_the_proxy_with_the_token_only() {
    let token = "scim-e2e-token-".to_owned() + &"y".repeat(24);
    let flag = format!("--scim-token={token}");
    let Some(d) = Deployment::start_with_args(&[flag.as_str()], &[]).await else {
        return;
    };
    let base = format!("https://localhost:{}/scim/v2", d.proxy_addr.port());
    let user = |name: &str| {
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": name, "active": true,
        })
    };
    for (http1_only, name) in [(true, "http1@example.com"), (false, "h2@example.com")] {
        let http = client(&d, http1_only);

        // No token, or a wrong one: refused, and nothing is created.
        let anonymous = http
            .post(format!("{base}/Users"))
            .json(&user(name))
            .send()
            .await
            .expect("request");
        assert_eq!(anonymous.status().as_u16(), 401, "no token");
        let wrong = http
            .post(format!("{base}/Users"))
            .bearer_auth("not-the-token")
            .json(&user(name))
            .send()
            .await
            .expect("request");
        assert_eq!(wrong.status().as_u16(), 401, "wrong token");

        // The token creates the person, and the response says who.
        let created = http
            .post(format!("{base}/Users"))
            .bearer_auth(&token)
            .header("content-type", "application/scim+json")
            .body(user(name).to_string())
            .send()
            .await
            .expect("request");
        assert_eq!(created.status().as_u16(), 201);
        let body: serde_json::Value = created.json().await.expect("json");
        assert_eq!(body["userName"], name);
        assert_eq!(body["active"], true);

        // Okta's look-up by name finds them.
        let found: serde_json::Value = http
            .get(format!(
                "{base}/Users?filter=userName%20eq%20%22{}%22",
                name.replace('@', "%40")
            ))
            .bearer_auth(&token)
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("json");
        assert_eq!(found["totalResults"], 1);
    }
}

#[tokio::test]
async fn scim_is_off_without_a_token() {
    let Some(d) = Deployment::start_with_args(&[], &[]).await else {
        return;
    };
    let http = client(&d, true);
    let response = http
        .get(format!(
            "https://localhost:{}/scim/v2/Users",
            d.proxy_addr.port()
        ))
        .bearer_auth("anything-at-all-anything-at-all-0")
        .send()
        .await
        .expect("request");
    // Not served: the control plane's gRPC router answers "unimplemented"
    // (gRPC says so in a header, with HTTP status 200) or a plain 404.
    let unimplemented = response
        .headers()
        .get("grpc-status")
        .is_some_and(|v| v == "12");
    assert!(
        unimplemented || response.status().as_u16() == 404,
        "{}",
        response.status()
    );
    let text = response.text().await.expect("body");
    assert!(
        !text.contains("ListResponse"),
        "no SCIM answer without a token"
    );
}
