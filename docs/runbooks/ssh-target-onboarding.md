# Runbook: onboarding an SSH target

Limen never gives users keys that work on hosts directly. A target trusts the **Limen SSH user CA**. The worker serving the target presents a one-minute certificate from that CA for each session, for exactly one login.

## 1. Trust the Limen SSH user CA on the host

Get the CA's public key from the control plane's exported CA directory (`ssh-user-ca.pub`), or from an admin. Then on the host:

```sh
sudo install -m 0644 ssh-user-ca.pub /etc/ssh/limen-user-ca.pub
sudo tee /etc/ssh/sshd_config.d/limen.conf >/dev/null <<'CONF'
TrustedUserCAKeys /etc/ssh/limen-user-ca.pub
# The certificate must list the login as a principal (the default without
# AuthorizedPrincipalsFile). Log certificate key IDs, which name the Limen
# session and user.
LogLevel VERBOSE
CONF
sudo sshd -t && sudo systemctl reload sshd
```

The logins you grant in policy must exist on the host. Accounts may be locked for passwords (`*` in `/etc/shadow`), but not disabled (`!`) on systems where sshd treats that as locked for all methods.

Optional hardening, if the host is only reached through Limen: `AuthorizedKeysFile none`, `PasswordAuthentication no`, `AllowAgentForwarding no`, `AllowTcpForwarding no`.

## 2. Pin the host key in policy

```sh
ssh-keyscan -t ed25519 web-1.internal 2>/dev/null | cut -d' ' -f2,3
```

Check the fingerprint out of band (cloud console, image build log). Then:

```yaml
kind: resource
version: v1
metadata: { name: web-1, labels: { env: prod } }
spec:
  ssh: { address: "web-1.internal:22", host_key: "ssh-ed25519 AAAA..." }
  worker_selector: { pool: prod-vpc }
```

Without `host_key`, the worker refuses the resource. When the host key changes (for example on a rebuild), update the pin.

## 3. Check

```sh
limen ls                                  # the resource shows up with its logins
limen ssh web-1 -- hostname
sudo journalctl -u sshd | grep 'Accepted certificate ID "limen:'
```

| Symptom | Cause |
|---|---|
| `worker couldn't open the session: resource has no pinned host_key` | Add `host_key` to the resource |
| `the target rejected the session certificate` | `TrustedUserCAKeys` missing or pointing at the wrong CA; or the login doesn't exist on the host |
| `target host key doesn't match the pinned key` (worker log) | Host key changed or the address points elsewhere. Investigate before re-pinning |
| `no worker is connected that can reach web-1` | No worker carries labels matching `worker_selector` |
| `access denied to root@web-1` | Policy doesn't grant that login. Check `limen ls` |
