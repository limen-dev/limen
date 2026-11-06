# Verifying the audit hash chain

Each control plane writes its S3 batches with a signed manifest that names the previous manifest's hash (ADR-0009). `limen audit verify` walks every writer's chain and reports a missing, reordered, modified, or unsigned batch.

```sh
limen login                  # as an auditor or admin
limen audit verify
```

**Who can run it.** Admins and auditors (`limen:admin` or `limen:auditor`), signed in. Limen checks your role, records an `audit.verify_access` event, and lends your session short-lived, read-only access to the audit bucket. The check itself runs on your machine against the CA pinned at login, so it does not rest on Limen's word. A developer gets `permission denied`. There is no bucket flag: the control plane decides which bucket, and your own AWS credentials are never used.

**Setting it up.** In the audit Terraform module, set `verifier_trusted_principal_arns` to the control plane's role. That creates the verifier role with the read-only policy (`verifier_policy_json`: read on the bucket, `kms:Decrypt`). Give the control plane's own role the `assume_verifier_policy_json` output, and set `LIMEN_AUDIT_VERIFIER_ROLE_ARN` to `verifier_role_arn`. Optional: `LIMEN_AUDIT_VERIFIER_TTL` (default 15 minutes) and `LIMEN_AUDIT_VERIFIER_S3_ENDPOINT` if people reach S3 by a different endpoint than the control plane does. Without a verifier role the command fails with "verification access is not set up". Verified only against local stand-ins, not real STS.

**Without a login.** Packs from `limen admin evidence` check offline with `limen audit verify --evidence <file> --ca-file internal-ca.pem`. No access to Limen or AWS is needed, so this is how someone outside the organization checks.

Exit code 0 and `OK: every batch is present, unmodified, signed, and chained` means the trail is intact. Exit code 2 prints one `PROBLEM:` line per finding.

| Problem | Likely cause |
|---|---|
| `was modified (hash mismatch)` | Someone replaced a batch. With bucket versioning, list the object's versions to see the original. |
| `sequence N found where M was expected` | A batch or manifest was deleted. |
| `chain broken` | A manifest was changed or removed. |
| `signature` | The manifest isn't signed by a control plane certificate from this CA (wrong CA, or a forged manifest). |
| `GAP` (a producer's sequence numbers are missing) | Events that were acknowledged and never shipped: an `ephemeral` control plane replica killed without warning, a spool lost with its disk (a proxy on an `emptyDir`), or events dropped in `degrade` failure mode. A gap names the producer and the missing numbers. It is part of the history, so **every later run reports it again**: record it in your incident notes rather than trying to clear it. A producer whose first number is not 0 has lost its first events. |
| `CONFLICT` (one sequence number on two different events) | Two producers sharing an instance id, or a tampered event. Treat as a security incident. |

A recovered original from a prior version restores the chain. Otherwise treat it as a security incident: the Datadog copy and the control plane's local spool may still hold the events.

**What it can't show:** events after the last manifest haven't been chained yet (they appear with the next batch), and the chain can't prove a control plane never wrote a false event.
