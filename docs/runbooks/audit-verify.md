# Verifying the audit hash chain

Each control plane writes its S3 batches with a signed manifest that names the previous manifest's hash (ADR-0009). `limen-audit-verify` walks every writer's chain and reports a missing, reordered, modified, or unsigned batch.

```sh
# From the control plane container (it has the CA files):
docker compose exec control-plane limen-audit-verify \
  --ca-file /var/lib/limen/ca-public/internal-ca.pem   # bucket and endpoint come from the environment

# From anywhere with read access to the bucket:
limen-audit-verify --bucket <bucket> [--prefix <p>] --ca-file internal-ca.pem
```

Needs the `verifier_policy_json` permissions (read-only on the bucket, `kms:Decrypt`). Exit code 0 and `OK: every batch is present, unmodified, signed, and chained` means the trail is intact. Exit code 2 prints one `PROBLEM:` line per finding.

| Problem | Likely cause |
|---|---|
| `was modified (hash mismatch)` | Someone replaced a batch. With bucket versioning, list the object's versions to see the original. |
| `sequence N found where M was expected` | A batch or manifest was deleted. |
| `chain broken` | A manifest was changed or removed. |
| `signature` | The manifest isn't signed by a control plane certificate from this CA (wrong `--ca-file`, or a forged manifest). |

A recovered original from a prior version restores the chain. Otherwise treat it as a security incident: the Datadog copy and the control plane's local spool may still hold the events.

**What it can't show:** events after the last manifest haven't been chained yet (they appear with the next batch), and the chain can't prove a control plane never wrote a false event.
