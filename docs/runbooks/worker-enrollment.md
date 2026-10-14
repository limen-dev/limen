# Runbook: enrolling proxies and workers

## Enroll a worker with a single-use token (preferred)

1. As an admin, create a token. It's valid for 15 minutes by default and works once.
   ```sh
   limen admin token create --kind worker --label pool=payments-vpc --ttl 30m
   ```
2. Start the worker with the token. It only ever connects **out**, to the proxy on 443.
   ```sh
   limen-worker --proxy-addr limen.example.com:443 --proxy-name limen.example.com \
     --join-token "$TOKEN" --data-dir /var/lib/limen/worker
   ```
   For a proxy certificate issued by the Limen internal CA (the dev stack), also pass `--ca-file internal-ca.pem`.
3. Confirm it's up:
   ```sh
   limen admin components      # the worker appears with 2 tunnels
   ```

The worker stores its key (mode 0600) and certificate in `--data-dir`. A restart reuses them, and the token isn't needed again. Certificates last 24 hours and renew at half-life through the proxy.

## Symptoms and fixes

| Log line or error | Cause | Fix |
|---|---|---|
| `invalid, expired, or already used join token` | Token reused, expired, or created for the other kind | Create a new token with the right `--kind` |
| `DNS name … is not allowed by this join token` | A proxy asked for a name not on the token's or the control plane's allow list | Create the token with `--dns-name`, or add the name to `--proxy-dns-name` |
| `certificate in … expired at …` | The worker was offline longer than its certificate lifetime | Delete `--data-dir` and enroll again with a new token |
| `tunnel failed; reconnecting` in a loop | The proxy is unreachable, or rejects the worker's certificate | Check egress to the proxy on 443. Check the proxy logs for `rejected tunnel` |
| `enrollment failed; retrying … Unavailable` | Control plane or proxy still starting | Nothing to do: it retries with backoff |

## Static tokens (dev and bootstrap only)

`--static-join-token kind:token` on the control plane accepts a multi-use token for one kind. Use them only for the dev stack and to bootstrap autoscaled tasks until IAM join exists (ADR-0016). Keep them in Secrets Manager and rotate them. Every enrollment is audited as `worker.enroll` with `"token_type": "static"`.
