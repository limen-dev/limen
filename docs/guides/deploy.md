# Deploying Limen on AWS

**Unverified.** The Terraform modules and the Helm chart pass `terraform validate`, `helm lint` and `helm template`. Nobody has applied them to AWS or installed the chart on a cluster (issues #80, #85). Expect to fix things on the first real run, and tell us what.

## What a deployment needs

| Part | Terraform (`modules/foundation`) | You |
|---|---|---|
| PostgreSQL (RDS, TLS forced) and its URL secret | creates | |
| Four KMS signing keys (`ECC_NIST_P256`, `SIGN_VERIFY`) | creates | |
| S3 audit store, Athena, Glue (`modules/audit`) | creates | |
| Join tokens for every proxy and worker group, and the control plane's `LIMEN_STATIC_JOIN_TOKENS` | creates (Secrets Manager) | |
| Secret for the internal CA certificate | creates | |
| IAM: control plane can sign with the keys and write audit | creates (role for EKS via IRSA) | |
| VPC, load balancers, services | `examples/complete` creates | |
| Identity provider client (OIDC issuer, client id) | | create it; pass issuer and client id |
| Public DNS name of each proxy | | point it at the load balancer |
| A TLS certificate the proxy serves publicly | | **not wired yet**, see below |
| EKS cluster | | bring your own |

Generated secrets (database password, join tokens) are in Terraform state. Use an encrypted remote backend with restricted access.

## Everything on ECS and EC2: `examples/complete`

```sh
cd deploy/terraform/examples/complete
cp terraform.tfvars.example my.tfvars   # edit: images, OIDC, proxy names, worker VPCs
terraform init
terraform apply -var-file=my.tfvars
```

It creates the VPC, the database, keys, audit store and secrets (foundation), an internal Network Load Balancer for the control planes, a public one per proxy, control planes and proxies on ECS Fargate, and worker groups on EC2 in the VPCs you name. Then point each proxy's public name at the load balancer (`terraform output proxy_dns_names`).

Scale by editing the maps: `desired_count` resizes an ECS service, and a new entry adds a group, such as another worker group in another VPC. On EC2, `desired_capacity` only sets the size at the first apply (Terraform then leaves the live count to your scaling policies); resize later with a scaling policy or `aws autoscaling set-desired-capacity`, and change `min_size` and `max_size` in the map.

**The internal CA.** Proxies and workers must trust the internal CA before they enroll, and only the control plane creates it. The control plane task runs a small sidecar (the AWS CLI image) that copies the exported `internal-ca.pem` into the `.../internal-ca` secret; proxy and worker tasks wait for it (an init container on ECS, a boot loop on EC2) and fail and retry until it is there. So the first apply brings up control planes first and the others settle within a few minutes. Helper image defaults are in `modules/ecs/variables.tf` (`helper_images`).

## On Kubernetes

Terraform creates what is not Kubernetes; the chart installs Limen. You bring the EKS cluster.

1. **Create the dependencies.**
   ```sh
   cd deploy/terraform/examples/kubernetes
   # my.tfvars: vpc_id, database_subnet_ids, node_cidrs, oidc, eks_oidc_provider_arn/url,
   #            proxies = { public = { dns_name = "limen.example.com" } }, worker_groups = ["prod-db"]
   terraform init && terraform apply -var-file=my.tfvars
   terraform output -raw helm_values > limen-values.yaml
   ```
2. **Create the Kubernetes secrets** from the outputs:
   ```sh
   kubectl create namespace limen
   out=$(terraform output -json kubernetes_secrets)
   kubectl -n limen create secret generic limen-database --from-literal=url="$(jq -r .database_url <<<"$out")"
   kubectl -n limen create secret generic limen-static-join-tokens --from-literal=tokens="$(jq -r .static_join_tokens <<<"$out")"
   kubectl -n limen create secret generic limen-proxy-public  --from-literal=token="$(jq -r '.join_tokens["proxy-public"]' <<<"$out")"
   kubectl -n limen create secret generic limen-worker-prod-db --from-literal=token="$(jq -r '.join_tokens["worker-prod-db"]' <<<"$out")"
   ```
3. **Write your values** next to `limen-values.yaml`: one entry per group, each naming its secret. `limen-values.yaml` already holds `namePrefix` for proxies and workers: the join tokens approve names that start with it, and the control plane refuses any other.
   ```yaml
   # image: the chart runs the release it was published with, from ghcr.io/limen-dev.
   # Set image: { registry: ghcr.io/your-org, tag: "v0.1.0" } to run a mirror or another release
   # (the tag has the v the release workflow gives the images).
   controlPlanes: { core: {} }
   proxies:
     public: { dnsNames: limen.example.com, joinSecret: limen-proxy-public }
   workers:
     prod-db: { proxy: public, joinSecret: limen-worker-prod-db }
   ```
4. **Install the control plane first.** The chart is published as an OCI artifact with each release; set `CHART=oci://ghcr.io/limen-dev/charts/limen` and `VERSION` to the release without its `v` (a pre-release is installable only by naming its version). From a checkout, `CHART=deploy/helm/limen` and leave out `--version`. The proxies and workers need the internal CA, which the control plane creates, so install with only the control plane, publish the CA, then add the rest:
   ```sh
   helm install limen "$CHART" --version "$VERSION" -n limen -f limen-values.yaml -f my-values.yaml \
     --set-json 'proxies={}' --set-json 'workers={}'
   kubectl -n limen rollout status statefulset/control-plane-core
   # The image has no shell: read the file through an ephemeral debug container.
   kubectl -n limen debug control-plane-core-0 --image=busybox:1.37.0 --target=control-plane-core -q -- \
     cat /proc/1/root/var/lib/limen/ca-public/internal-ca.pem > internal-ca.pem
   kubectl -n limen create configmap limen-internal-ca --from-file=internal-ca.pem
   helm upgrade limen "$CHART" --version "$VERSION" -n limen -f limen-values.yaml -f my-values.yaml
   ```
5. **Point the proxy's public name** at its load balancer (`kubectl -n limen get svc proxy-public`).

The `limen-values.yaml` includes the IRSA role annotation, so the control plane can reach KMS and S3 without keys. The debug-container step is unverified; if your cluster disallows ephemeral containers, `kubectl cp` needs `tar`, which the image lacks, so mount the export directory on a volume instead.

## Discovery

Workers can find EC2 instances, databases, caches and clusters ([discovery guide](discovery.md)). Set `discovery = true` on a worker group in `examples/complete`: it sets `LIMEN_DISCOVERY` and creates the describe-only role through `modules/discovery`; use the `discovery_role_arn` output as `role_arn` in your discovery document. On Kubernetes, apply `modules/discovery` with your worker IRSA role in `worker_role_arns`, then set `discovery: true` and `serviceAccount.annotations` on the worker group. Discovery in other accounts needs one `modules/discovery` per account and the `assume_policy_arn` on the worker role.

## After it runs

- **Scale, replace and upgrade** copies with the [scale-out runbook](../runbooks/scale-out.md). Never roll one replica back after another has migrated the database.
- **Metrics.** Every component serves `/metrics` on its admin port (3081, 3444, 3090), unauthenticated, so keep it private. On ECS and EC2 open it to your scraper or load balancer with `admin_ingress_cidrs` on the service or group; in the chart set `podAnnotations` on a group (`prometheus.io/scrape`, `/port`, `/path`).
- **Register what you build** from Terraform or OpenTofu with the [Limen provider](terraform.md). That is separate from the modules here, which deploy Limen itself. The provider is unreleased and unverified against a real control plane.

## The proxy's public certificate
Users should not need a CA file. Give each proxy a certificate from a public CA (Let's Encrypt, a commercial CA, or an exported ACM certificate) and users run `limen login --server limen.example.com` with nothing else.

| Flag | Environment | |
|---|---|---|
| `--public-cert-file` | `LIMEN_PUBLIC_CERT_FILE` | PEM chain, leaf first |
| `--public-key-file` | `LIMEN_PUBLIC_KEY_FILE` | PEM private key. Mount it read-only, readable by the proxy only |

Either flag needs the other. Without them nothing changes.

- **Terminate TLS at the proxy, not at a load balancer.** Users present client certificates, so the load balancer must pass TCP through; an ACM certificate attached to a load balancer will not work.
- **Names.** The certificate must cover the name users type, and the console and web app hosts (a wildcard such as `*.apps.example.com` for apps).
- **Who sees which certificate.** The CLI and browsers get the public one. Workers and peer proxies keep getting the one the internal CA issued, and still pin the internal CA, so they need nothing. Upgrade workers before you switch this on: a worker from before ADR-0043 cannot be told from the CLI.
- **Renewal.** The proxy reads both files again every minute and on `SIGHUP`. A file that does not parse, has expired, or whose key does not match the certificate is refused, and the last good certificate stays in use with a warning in the log and `limen_proxy_public_cert_reload_failures_total` counting up. Files that are missing, not PEM, or whose key does not match stop the proxy at start-up rather than serve the wrong certificate. An *expired* certificate does not: the proxy is also how workers and peers reach each other, so it starts, logs an error, and the expiry alert is already firing.
- **Watch the expiry.** `limen_proxy_public_cert_expiry_timestamp_seconds` is the leaf's `notAfter`. Alert when `expiry - time()` drops under about 14 days: the proxy keeps serving an expired certificate it cannot replace, and users then get a trust error.
- **Existing users must drop their pinned CA.** Before this, the CLI refused to connect without a CA, so everyone who has logged in has the internal CA pinned, and a pinned CA wins. `limen logout` keeps it on purpose. Once you switch the certificate on, their commands fail with "the server's certificate isn't trusted". Tell them to run `limen login --server limen.example.com --system-roots` once; it forgets the old pin and checks the system trust store from then on. New users and new CI machines need nothing. Servers that keep their own CA are unaffected.
- **Audit verification still needs the internal CA.** `limen audit verify` checks signatures against Limen's own CA, not the system's: pass `--ca-file`.

## Not covered yet

- **Provisioning the proxy's public TLS certificate.** The proxy takes a PEM chain and key from a public CA (`--public-cert-file`, `--public-key-file`; [ADR-0043](../adr/0043-public-proxy-certificate.md)), but nothing here issues or mounts one yet. Until you do, the CLI and browsers need the internal CA (`limen login --ca-file`). See [the public certificate](#the-proxys-public-certificate) below for what to mount and how it renews.
- **Audit durability of control planes on ECS and EC2.** They run with `spool_mode = "ephemeral"`, because neither keeps its disk: a replica that dies before it hands over its spool loses the events not yet in S3 (up to `LIMEN_AUDIT_S3_FLUSH`, 60 s by default). The verifier reports them as gaps. For no loss, use the Kubernetes chart, whose StatefulSet keeps a volume (`durable`). See [running Limen at scale](scale-out.md).
- **First admin.** Set `LIMEN_BOOTSTRAP_ADMIN_GROUPS` (extra environment) so the first admin can log in and apply policy. The [Okta guide](okta.md) shows the identity provider side.
