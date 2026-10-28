# ADR-0007: Three CA keys behind a Signer trait, with KMS in production

- Status: Accepted (owner approved 2026-10-13)
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

## Amendment (Phase 2, 2026-10-14): two SSH CAs, per-session certificates
- **SSH user CA** (`user_ssh`): trusted by targets (`TrustedUserCAKeys`). It signs only per-session user certificates, at the request of a worker presenting a valid proxy grant. Each certificate has one principal (the granted login), lives for 1 minute (plus 1 minute of back-dating), carries key ID `limen:<session>:<user>`, and grants only `permit-pty`. It's issued once per grant.
- **SSH host CA** (`host_ssh`): trusted by the CLI through `@cert-authority` in the profile's known_hosts. It signs per-session host certificates for the worker's ephemeral host key, with principals `<resource>` and `<resource>.limen`, valid for 5 minutes.
- **No SSH certificate at login.** The original design issued one, signed by the CA that targets trust. Anyone holding it could have reached targets directly when the network allowed, skipping the proxy, the recording, and the audit trail. The user's SSH client authenticates to the worker with `none` on a stream that mTLS and the grant already authenticate.
- Both SSH CAs use the `Signer` trait, so they can live in KMS. KMS's DER ECDSA signature is converted to the SSH `mpint(r) || mpint(s)` form (`limen_ca::ssh::der_to_ssh_ecdsa`), and this is tested against local-kms.

## Consequences
- \+ CA private keys never exist outside KMS in production.
- − Signing costs one KMS call per cert. At the target scale (500 users × a few certs an hour, plus one SSH certificate per session) that's far below the quotas. *Check the current KMS quota for asymmetric `Sign` in Phase 1.*
- − KMS being down blocks logins and new SSH sessions (see ADR-0011).
