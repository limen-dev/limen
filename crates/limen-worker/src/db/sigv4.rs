//! AWS Signature Version 4, the two forms the database paths need (ADR-0033):
//! a presigned query string (RDS and Aurora IAM authentication tokens) and
//! signed request headers (Redshift's credential APIs).
//!
//! Written against the specification and checked against the examples AWS
//! publishes (see the tests). Checked only against those: no AWS account has
//! been available, so this is *unverified against the real services*.

use aws_lc_rs::{digest, hmac};
use limen_core::secret::Secret;
use time::OffsetDateTime;
use time::macros::format_description;

/// The payload hash of an empty body.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: Secret<String>,
    pub session_token: Option<Secret<String>>,
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// SHA-256 of `data`, as lower-case hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

/// RFC 3986 percent-encoding as `SigV4` wants it: only the characters `A-Za-z0-9-_.~` stay.
/// With `keep_slash` the path separator stays too.
#[must_use]
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            b'/' if keep_slash => out.push('/'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Encode, sort, and join query parameters.
#[must_use]
pub fn canonical_query(params: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)`.
fn stamps(now: OffsetDateTime) -> (String, String) {
    let utc = now.to_offset(time::UtcOffset::UTC);
    let date = utc
        .format(format_description!("[year][month][day]"))
        .unwrap_or_default();
    let stamp = utc
        .format(format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .unwrap_or_default();
    (date, stamp)
}

fn sign_string(
    secret: &str,
    date: &str,
    stamp: &str,
    region: &str,
    service: &str,
    canonical: &str,
) -> String {
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{date}/{region}/{service}/aws4_request\n{}",
        sha256_hex(canonical.as_bytes())
    );
    hex(&hmac_sha256(
        &signing_key(secret, date, region, service),
        to_sign.as_bytes(),
    ))
}

/// What a signing call needs to know about the request.
#[derive(Debug)]
pub struct Target<'a> {
    pub method: &'a str,
    /// `host` or `host:port`, as it will be sent.
    pub host: &'a str,
    pub path: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

/// A presigned query string: the given parameters plus the `X-Amz-*` ones and
/// the signature, sorted. Only the `host` header is signed.
#[must_use]
pub fn presign_query(
    target: &Target<'_>,
    params: &[(String, String)],
    creds: &Credentials,
    expires_secs: u32,
    payload_hash: &str,
    now: OffsetDateTime,
) -> String {
    let (date, stamp) = stamps(now);
    let scope = format!("{date}/{}/{}/aws4_request", target.region, target.service);
    let mut all: Vec<(String, String)> = params.to_vec();
    all.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
    all.push((
        "X-Amz-Credential".into(),
        format!("{}/{scope}", creds.access_key),
    ));
    all.push(("X-Amz-Date".into(), stamp.clone()));
    all.push(("X-Amz-Expires".into(), expires_secs.to_string()));
    all.push(("X-Amz-SignedHeaders".into(), "host".into()));
    if let Some(token) = &creds.session_token {
        all.push(("X-Amz-Security-Token".into(), token.expose().clone()));
    }
    let query = canonical_query(&all);
    let canonical = format!(
        "{}\n{}\n{query}\nhost:{}\n\nhost\n{payload_hash}",
        target.method,
        uri_encode(target.path, true),
        target.host
    );
    let signature = sign_string(
        creds.secret_key.expose(),
        &date,
        &stamp,
        target.region,
        target.service,
        &canonical,
    );
    format!("{query}&X-Amz-Signature={signature}")
}

/// The headers to add to a request signed with header authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub authorization: String,
    pub amz_date: String,
    pub payload_hash: String,
    pub session_token: Option<String>,
}

/// Sign a request whose headers (besides `host`, `x-amz-date`, and the
/// session token) are `extra`, given as lower-case name and trimmed value.
#[must_use]
pub fn sign_headers(
    target: &Target<'_>,
    query: &str,
    extra: &[(&str, &str)],
    body: &[u8],
    creds: &Credentials,
    now: OffsetDateTime,
) -> SignedHeaders {
    use std::fmt::Write as _;
    let (date, stamp) = stamps(now);
    let payload_hash = sha256_hex(body);
    let mut headers: Vec<(String, String)> = extra
        .iter()
        .map(|(k, v)| ((*k).to_ascii_lowercase(), (*v).trim().to_owned()))
        .collect();
    headers.push(("host".into(), target.host.to_owned()));
    headers.push(("x-amz-date".into(), stamp.clone()));
    if let Some(token) = &creds.session_token {
        headers.push(("x-amz-security-token".into(), token.expose().clone()));
    }
    headers.sort();
    let canonical_headers = headers.iter().fold(String::new(), |mut acc, (k, v)| {
        let _ = writeln!(acc, "{k}:{v}");
        acc
    });
    let signed = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{}\n{}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}",
        target.method,
        uri_encode(target.path, true),
    );
    let signature = sign_string(
        creds.secret_key.expose(),
        &date,
        &stamp,
        target.region,
        target.service,
        &canonical,
    );
    SignedHeaders {
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{date}/{}/{}/aws4_request, SignedHeaders={signed}, Signature={signature}",
            creds.access_key, target.region, target.service
        ),
        amz_date: stamp,
        payload_hash,
        session_token: creds.session_token.as_ref().map(|t| t.expose().clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).expect("time")
    }

    // "Authenticating Requests: Using Query Parameters (AWS Signature
    // Version 4)", Amazon S3 documentation.
    #[test]
    fn matches_the_published_presigned_url_example() {
        let creds = Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: Secret::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
            session_token: None,
        };
        let query = presign_query(
            &Target {
                method: "GET",
                host: "examplebucket.s3.amazonaws.com",
                path: "/test.txt",
                region: "us-east-1",
                service: "s3",
            },
            &[],
            &creds,
            86_400,
            "UNSIGNED-PAYLOAD",
            at("2013-05-24T00:00:00Z"),
        );
        assert_eq!(
            query,
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    // AWS Signature Version 4 test suite, "get-vanilla".
    #[test]
    fn matches_the_published_header_signature_example() {
        let creds = Credentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: Secret::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into()),
            session_token: None,
        };
        let signed = sign_headers(
            &Target {
                method: "GET",
                host: "example.amazonaws.com",
                path: "/",
                region: "us-east-1",
                service: "service",
            },
            "",
            &[],
            b"",
            &creds,
            at("2015-08-30T12:36:00Z"),
        );
        assert_eq!(signed.amz_date, "20150830T123600Z");
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn encoding_and_sorting() {
        assert_eq!(uri_encode("a b/c~d", false), "a%20b%2Fc~d");
        assert_eq!(uri_encode("/a b", true), "/a%20b");
        let q = canonical_query(&[
            ("b".into(), "2".into()),
            ("a".into(), "x y".into()),
            ("a".into(), "1".into()),
        ]);
        assert_eq!(q, "a=1&a=x%20y&b=2");
        assert_eq!(sha256_hex(b""), EMPTY_PAYLOAD_SHA256);
    }

    #[test]
    fn a_session_token_is_signed() {
        let creds = Credentials {
            access_key: "AK".into(),
            secret_key: Secret::new("sk".into()),
            session_token: Some(Secret::new("tok/en".into())),
        };
        let q = presign_query(
            &Target {
                method: "GET",
                host: "h:1",
                path: "/",
                region: "r",
                service: "rds-db",
            },
            &[("Action".into(), "connect".into())],
            &creds,
            900,
            EMPTY_PAYLOAD_SHA256,
            at("2026-10-17T00:00:00Z"),
        );
        assert!(q.contains("X-Amz-Security-Token=tok%2Fen"), "{q}");
        assert!(q.starts_with("Action=connect&X-Amz-Algorithm="), "{q}");
        assert!(q.contains("&X-Amz-Signature="));
    }
}
