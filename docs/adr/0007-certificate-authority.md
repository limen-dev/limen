# ADR-0007: Three CA keys behind a Signer trait, with KMS in production

- Status: Proposed
- Date: 2026-10-13

## Decision
- Keys per purpose:
  - **internal** (mTLS between components)
  - **user-x509** (user client certs)
  - **user-ssh** (OpenSSH user certs)
  - later, an optional **host-ssh** key for target host certs
- `limen_ca::Signer` trait backends: `FileSigner` (dev and tests, PKCS#8 on disk with mode 0600) and `KmsSigner` (production: `ECC_NIST_P256`, `SIGN_VERIFY`, `ECDSA_SHA_256`, `MessageType=RAW`).
- KMS returns **DER** ECDSA signatures (ANSI X9.62 / RFC 3279). X.509 uses DER directly. For OpenSSH certs we convert to the `ecdsa-sha2-nistp256` signature format (`string "ecdsa-sha2-nistp256"`, `string (mpint r ‖ mpint s)`), and test against `ssh-keygen -L` and real sshd.
- X.509 cert building uses `rcgen` with a remote-key signing adapter. If rcgen can't sign through an external signer cleanly, the fallback is building the TBSCertificate with the RustCrypto `x509-cert` crate. *Spike in Phase 1.*
- **Rotation:** a CA has states `active` and `additional_trusted`. New keys are trusted first and used for signing later. The old key stays trusted for at least `max_cert_ttl` plus clock skew (5 min). For SSH, `TrustedUserCAKeys` lists both keys during the overlap.
- `kms:Sign` is granted only to the control plane task role, with a key-policy condition on `kms:SigningAlgorithm`.

## Consequences
- \+ CA private keys never exist outside KMS in production.
- − Signing costs one KMS call per cert. At the target scale (500 users × a few certs every 10 min) that's far below the quotas. *Check the current KMS quota for asymmetric `Sign` in Phase 1.*
- − KMS being down blocks logins and new SSH sessions (see ADR-0011).
