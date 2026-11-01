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
3. **Write your values** next to `limen-values.yaml`: the image, and one entry per group, each naming its secret.
   ```yaml
   image: { registry: ghcr.io/your-org, tag: "0.1.0" }
   controlPlanes: { core: {} }
   proxyDefaults: { namePrefix: prod }
   proxies:
     public: { dnsNames: limen.example.com, joinSecret: limen-proxy-public }
   workerDefaults: { namePrefix: prod }
   workers:
     prod-db: { proxy: public, joinSecret: limen-worker-prod-db }
   ```
4. **Install the control plane first.** The proxies and workers need the internal CA, which the control plane creates, so install with only the control plane, publish the CA, then add the rest:
   ```sh
   helm install limen deploy/helm/limen -n limen -f limen-values.yaml -f my-values.yaml \
     --set-json 'proxies={}' --set-json 'workers={}'
   kubectl -n limen rollout status statefulset/control-plane-core
   # The image has no shell: read the file through an ephemeral debug container.
   kubectl -n limen debug control-plane-core-0 --image=busybox:1.37.0 --target=control-plane-core -q -- \
     cat /proc/1/root/var/lib/limen/ca-public/internal-ca.pem > internal-ca.pem
   kubectl -n limen create configmap limen-internal-ca --from-file=internal-ca.pem
   helm upgrade limen deploy/helm/limen -n limen -f limen-values.yaml -f my-values.yaml
   ```
5. **Point the proxy's public name** at its load balancer (`kubectl -n limen get svc proxy-public`).

The `limen-values.yaml` includes the IRSA role annotation, so the control plane can reach KMS and S3 without keys. The debug-container step is unverified; if your cluster disallows ephemeral containers, `kubectl cp` needs `tar`, which the image lacks, so mount the export directory on a volume instead.

## Discovery

Workers can find EC2 instances, databases, caches and clusters ([discovery guide](discovery.md)). Set `discovery = true` on a worker group in `examples/complete`: it sets `LIMEN_DISCOVERY` and creates the describe-only role through `modules/discovery`; use the `discovery_role_arn` output as `role_arn` in your discovery document. On Kubernetes, apply `modules/discovery` with your worker IRSA role in `worker_role_arns`, then set `discovery: true` and `serviceAccount.annotations` on the worker group. Discovery in other accounts needs one `modules/discovery` per account and the `assume_policy_arn` on the worker role.

## Not covered yet

- **The proxy's public TLS certificate.** Design §91 leaves it open (ACM exportable certificate or one supplied from Secrets Manager). The load balancers pass TCP through, as the design requires, and nothing here provisions the certificate. This blocks real browser and CLI trust until it is decided.
- **Control plane replica identity.** Kubernetes StatefulSet pods have stable ids. ECS tasks and Auto Scaling instances do not, and Fargate has no persistent audit spool, so test control planes on ECS and EC2 before trusting them with audit data.
- **First admin.** Set `LIMEN_BOOTSTRAP_ADMIN_GROUPS` (extra environment) so the first admin can log in and apply policy.
