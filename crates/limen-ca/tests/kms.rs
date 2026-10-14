//! The KMS signer against a KMS emulator (local-kms in the dev stack).
//! Set `LIMEN_TEST_KMS_ENDPOINT` (for example `http://localhost:8099`) to run.
//!
//! This proves the property ADR-0007 relies on: KMS's DER ECDSA signatures
//! drop straight into X.509 certificates that verify offline. It doesn't
//! prove AWS-specific behavior (quotas, latency, IAM): unverified against
//! the real service until an AWS account exists.

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_kms::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_kms::types::{KeySpec, KeyUsageType};
use limen_ca::kms::KmsSigner;
use limen_ca::verify::verify_user;
use limen_ca::{CaPurpose, CertificateAuthority, Signer, UserCertRequest};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

fn client(endpoint: &str) -> aws_sdk_kms::Client {
    let config = aws_sdk_kms::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("eu-west-1"))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new("test", "test", None, None, "static"))
        .build();
    aws_sdk_kms::Client::from_conf(config)
}

async fn create_key(client: &aws_sdk_kms::Client, spec: KeySpec, usage: KeyUsageType) -> String {
    client
        .create_key()
        .key_spec(spec)
        .key_usage(usage)
        .send()
        .await
        .expect("create key")
        .key_metadata()
        .expect("metadata")
        .key_id()
        .to_owned()
}

#[tokio::test]
async fn kms_backed_ca_issues_certificates_that_verify() {
    let Ok(endpoint) = std::env::var("LIMEN_TEST_KMS_ENDPOINT") else {
        eprintln!("SKIPPED: LIMEN_TEST_KMS_ENDPOINT is not set");
        return;
    };
    let client = client(&endpoint);
    let key_id = create_key(&client, KeySpec::EccNistP256, KeyUsageType::SignVerify).await;
    let signer: Arc<dyn Signer> =
        Arc::new(KmsSigner::new(client, &key_id).await.expect("kms signer"));

    let ca = CertificateAuthority::create_self_signed(CaPurpose::UserX509, signer)
        .await
        .expect("self-signed CA via KMS");
    let user_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let csr = CertificateParams::default()
        .serialize_request(&user_key)
        .expect("csr");
    let issued = ca
        .issue_user(UserCertRequest {
            csr_der: csr.der().to_vec(),
            username: "admin@example.com".into(),
            roles: vec!["sre".into()],
            login_id: uuid::Uuid::now_v7(),
            ttl: Duration::from_secs(600),
        })
        .await
        .expect("issue via KMS");
    // The CA cert is self-signed by KMS, the leaf is signed by KMS: webpki
    // checks both signatures.
    let identity = verify_user(&issued.der, ca.cert_der()).expect("KMS-signed chain verifies");
    assert_eq!(identity.username, "admin@example.com");
}

#[tokio::test]
async fn kms_signer_rejects_wrong_key_types() {
    let Ok(endpoint) = std::env::var("LIMEN_TEST_KMS_ENDPOINT") else {
        eprintln!("SKIPPED: LIMEN_TEST_KMS_ENDPOINT is not set");
        return;
    };
    let client = client(&endpoint);
    let rsa = create_key(&client, KeySpec::Rsa2048, KeyUsageType::SignVerify).await;
    assert!(
        KmsSigner::new(client.clone(), &rsa).await.is_err(),
        "RSA keys must be rejected"
    );
    let symmetric = create_key(
        &client,
        KeySpec::SymmetricDefault,
        KeyUsageType::EncryptDecrypt,
    )
    .await;
    assert!(
        KmsSigner::new(client, &symmetric).await.is_err(),
        "encryption keys must be rejected"
    );
}

#[tokio::test]
async fn kms_backed_ssh_ca_issues_valid_certificates() {
    use limen_ca::ssh::{SshCa, SshUserCertRequest};
    let Ok(endpoint) = std::env::var("LIMEN_TEST_KMS_ENDPOINT") else {
        eprintln!("SKIPPED: LIMEN_TEST_KMS_ENDPOINT is not set");
        return;
    };
    let client = client(&endpoint);
    let key_id = create_key(&client, KeySpec::EccNistP256, KeyUsageType::SignVerify).await;
    let signer: Arc<dyn Signer> =
        Arc::new(KmsSigner::new(client, &key_id).await.expect("kms signer"));
    let ca = SshCa::new(CaPurpose::UserSsh, signer).expect("ssh ca");
    let user =
        ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).expect("key");
    let cert = ca
        .issue_user_cert(SshUserCertRequest {
            public_key: user.public_key().clone(),
            principal: "ubuntu".into(),
            key_id: "session".into(),
            ttl: Duration::from_secs(60),
            permit_pty: true,
            permit_port_forwarding: false,
        })
        .await
        .expect("issue via KMS");
    // KMS's DER signature, converted to the SSH mpint form, validates.
    cert.validate([&ca.public_key().fingerprint(ssh_key::HashAlg::Sha256)])
        .expect("KMS-signed SSH certificate validates");
}
