<!-- Generated: edit README.md.gotmpl and values.yaml, then run `mise exec -- helm-docs --chart-search-root deploy/helm --sort-values-order file`. CI checks it is current. -->
# Limen Helm chart

Runs the control plane (StatefulSet, headless Service, PodDisruptionBudget), the proxy (Deployment, `LoadBalancer` Service) and the workers (Deployment). It templates the manifests in [`deploy/kubernetes/limen`](../../kubernetes/limen/README.md); read that README for why each setting looks the way it does.

**Unverified:** the chart passes `helm lint` and `helm template` (CI runs both) but was never installed on a cluster. Issue #85 tracks the real-cluster test.

```sh
kubectl create secret generic limen-database --from-literal=url='postgres://...'
kubectl create secret generic limen-proxy-join  --from-literal=token=...
kubectl create secret generic limen-worker-join --from-literal=token=...
kubectl create configmap limen-internal-ca --from-file=internal-ca.pem

helm install limen oci://ghcr.io/limen-dev/charts/limen --version 0.1.0-rc.2 -f my-values.yaml
# or from a checkout: helm install limen deploy/helm/limen -f my-values.yaml
```

Each release pushes the chart to `ghcr.io/<owner>/charts/limen` with `version` and `appVersion` set to the release, after the images it refers to are published; without `image.tag` the chart runs that release (the images are tagged `v<version>`). **Unverified:** the push has not run yet, because no release has been cut with it.

## More than one of each

`controlPlanes`, `proxies` and `workers` are maps; **each entry is one more group** (a StatefulSet or Deployment, with its Service and PodDisruptionBudget). An entry overrides `controlPlaneDefaults`, `proxyDefaults` or `workerDefaults`, so it lists only what differs, and its key is part of every resource name (`worker-prod-db`, `proxy-public`, `control-plane-core`):

```yaml
proxies:
  public:  { dnsNames: limen.example.com }
  partner: { dnsNames: partner.example.com, replicas: 2, joinSecret: partner-proxy-join }
workers:
  prod-db: { proxy: public, replicas: 5 }
  staging: { proxy: public, joinSecret: staging-worker-join, nodeSelector: { pool: staging } }
```

- A proxy dials `controlPlane` (a key; default: the first) or `controlPlaneAddr`. A worker dials `proxy` (a key; default: the first), at the proxy's first DNS name on its service port, or at `proxyAddr` and `proxyName`.
- Each group can take its own join token with `joinSecret`, and its own `nodeSelector`, `tolerations` and `resources`, for example workers on dedicated nodes.
- Scale a group with `replicas`. Separate control plane groups are separate Limen deployments (their own database and keys); to scale one, raise its `replicas`.
- Run only workers, for example in another cluster against a proxy elsewhere, by leaving `controlPlanes` and `proxies` empty and setting `proxyAddr` and `proxyName` on each worker.

Values without a default fail the install with a message naming them: the OIDC issuer and client id, the audit bucket and the four KMS key ids (in `controlPlaneDefaults`), and the `namePrefix` and `dnsNames` of proxies and the `namePrefix` of workers. `ci-values.yaml` is a complete example with three worker groups and two proxy groups.

- Grace periods default to the drain times plus margin; a worker group refuses a grace period at or below its drain time.
- `podAnnotations` on a group adds pod annotations, for example `prometheus.io/scrape`, `prometheus.io/port` (the admin port: 3081, 3444 or 3090) and `prometheus.io/path: /metrics`. Scaling, replacing and upgrading copies: [scale-out runbook](../../../docs/runbooks/scale-out.md).
- Pods run as the images' nonroot uid with `fsGroup: 65532`, so the control plane's spool volume is writable; change `podSecurityContext` or `securityContext` per group if your cluster's policy needs it.
- A worker's `proxy` and a proxy's `controlPlane` must name a group that exists; a typo fails the install.
- On EKS, put the IAM role for KMS and S3 on a control plane's service account with `serviceAccount.annotations`.
- No HorizontalPodAutoscaler is included; the metric source differs between clusters (see the Kubernetes README).

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.registry | string | `"ghcr.io/limen-dev"` | Registry the images are pulled from. They are named limen-control-plane, limen-proxy and limen-worker. |
| image.tag | string | `""` | Limen release to run, as the image tag (v0.1.0). Empty runs the chart's appVersion, the release it was published with. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| imagePullSecrets | list | `[]` | Pull secrets for a private mirror of the images. |
| existingSecrets.database | string | `"limen-database"` | Secret with the database URL, key `url`. |
| existingSecrets.proxyJoin | string | `"limen-proxy-join"` | Default Secret with a proxy's join token, key `token`. |
| existingSecrets.workerJoin | string | `"limen-worker-join"` | Default Secret with a worker's join token, key `token`. |
| internalCA.configMap | string | `"limen-internal-ca"` | ConfigMap with the internal CA certificate, key `internal-ca.pem`. Proxies and workers trust it. |
| controlPlanes | object | `{}` | Control plane groups, by key. One StatefulSet per entry; each entry is a separate Limen deployment (own database and keys). REQUIRED unless you run no control plane. |
| controlPlaneDefaults.replicas | int | `3` | Replicas per group. |
| controlPlaneDefaults.drainTimeout | string | `"20s"` | How long a replica drains on SIGTERM (LIMEN_DRAIN_TIMEOUT). |
| controlPlaneDefaults.terminationGracePeriodSeconds | int | `45` | Must exceed drainTimeout by enough to finish the drain and the handoff. |
| controlPlaneDefaults.oidc.issuer | string | `""` | OIDC issuer URL. REQUIRED. |
| controlPlaneDefaults.oidc.clientId | string | `""` | OIDC client id. REQUIRED. |
| controlPlaneDefaults.auditS3Bucket | string | `""` | Audit S3 bucket name. REQUIRED. |
| controlPlaneDefaults.kms | object | `{"internalCaKey":"","sshHostCaKey":"","sshUserCaKey":"","userCaKey":""}` | ARNs of the four KMS signing keys of the KMS CA backend (ADR-0020). |
| controlPlaneDefaults.databaseSecret | string | `""` | Secret with the database URL. Empty uses existingSecrets.database. |
| controlPlaneDefaults.spool.size | string | `"10Gi"` | Size of the volume that holds the audit spool (`durable` mode). |
| controlPlaneDefaults.spool.storageClassName | string | `""` | Storage class of that volume. Empty uses the cluster default. |
| controlPlaneDefaults.pdb | object | `{"minAvailable":2}` | PodDisruptionBudget. It is capped so a node can always be drained. |
| controlPlaneDefaults.resources | object | `{"requests":{"cpu":"500m","memory":"512Mi"}}` | Container resources. |
| controlPlaneDefaults.extraEnv | list | `[]` | Extra environment variables, as in a container spec. |
| controlPlaneDefaults.podSecurityContext | object | `{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. fsGroup makes volumes writable by the nonroot image (uid 65532). |
| controlPlaneDefaults.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | Container security context. |
| controlPlaneDefaults.nodeSelector | object | `{}` | Node selector. |
| controlPlaneDefaults.podAnnotations | object | `{}` | Pod annotations, e.g. prometheus.io/scrape, /port (the admin port) and /path: /metrics. |
| controlPlaneDefaults.tolerations | list | `[]` | Tolerations. |
| controlPlaneDefaults.serviceAccount | object | `{"annotations":{},"create":true}` | Service account. Annotate it with the IRSA role for KMS and S3. |
| proxies | object | `{}` | Proxy groups, by key. One Deployment and LoadBalancer Service per entry. REQUIRED unless you run no proxy. |
| proxyDefaults.replicas | int | `3` | Replicas per group. |
| proxyDefaults.drainTimeoutSecs | int | `20` | How long a proxy drains on SIGTERM (LIMEN_DRAIN_TIMEOUT_SECS). |
| proxyDefaults.terminationGracePeriodSeconds | int | `40` | Must exceed drainTimeoutSecs. |
| proxyDefaults.namePrefix | string | `""` | Prefix of each proxy's name; the join token must approve it. REQUIRED. |
| proxyDefaults.dnsNames | string | `""` | Public DNS name(s) of the load balancer, comma separated. REQUIRED. |
| proxyDefaults.controlPlane | string | `""` | Key of the control plane group to dial. Empty uses the first. |
| proxyDefaults.controlPlaneAddr | string | `""` | Overrides controlPlane, e.g. "cp.other-cluster.example.com:3080". |
| proxyDefaults.joinSecret | string | `""` | Secret with this group's join token. Empty uses existingSecrets.proxyJoin. |
| proxyDefaults.service.type | string | `"LoadBalancer"` | Service type. |
| proxyDefaults.service.port | int | `443` | Service port. |
| proxyDefaults.service.annotations | object | `{"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type":"ip","service.beta.kubernetes.io/aws-load-balancer-type":"external"}` | Service annotations. The defaults ask AWS for a Network Load Balancer in TCP mode; TLS is end to end (ADR-0005). |
| proxyDefaults.pdb | object | `{"minAvailable":2}` | PodDisruptionBudget. It is capped so a node can always be drained. |
| proxyDefaults.resources | object | `{"requests":{"cpu":"250m","memory":"256Mi"}}` | Container resources. |
| proxyDefaults.extraEnv | list | `[]` | Extra environment variables, as in a container spec. |
| proxyDefaults.podSecurityContext | object | `{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. fsGroup makes volumes writable by the nonroot image (uid 65532). |
| proxyDefaults.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | Container security context. |
| proxyDefaults.nodeSelector | object | `{}` | Node selector. |
| proxyDefaults.podAnnotations | object | `{}` | Pod annotations, e.g. prometheus.io/scrape, /port (the admin port) and /path: /metrics. |
| proxyDefaults.tolerations | list | `[]` | Tolerations. |
| workers | object | `{}` | Worker groups, by key. One Deployment per entry. REQUIRED unless you run no worker. |
| workerDefaults.replicas | int | `3` | Replicas per group. |
| workerDefaults.maxSessions | int | `200` | Sessions a worker accepts at once (LIMEN_MAX_SESSIONS). |
| workerDefaults.drainTimeoutSecs | int | `300` | How long a worker lets open sessions finish on SIGTERM (LIMEN_DRAIN_TIMEOUT_SECS). |
| workerDefaults.terminationGracePeriodSeconds | int | `330` | Must exceed drainTimeoutSecs plus about 20 s to upload recordings. The chart refuses a smaller value. |
| workerDefaults.namePrefix | string | `""` | Prefix of each worker's name. REQUIRED. |
| workerDefaults.proxy | string | `""` | Key of the proxy group to dial. Empty uses the first. |
| workerDefaults.proxyAddr | string | `""` | Overrides proxy: host:port. |
| workerDefaults.proxyName | string | `""` | Overrides proxy: the proxy's certificate name. |
| workerDefaults.joinSecret | string | `""` | Secret with this group's join token. Empty uses existingSecrets.workerJoin. |
| workerDefaults.discovery | bool | `false` | Run resource discovery (ADR-0027); see docs/guides/discovery.md. |
| workerDefaults.serviceAccount | object | `{"annotations":{}}` | Service account. Annotate it with the IRSA role the worker uses (the one modules/discovery trusts); any annotation creates the service account. |
| workerDefaults.resources | object | `{"requests":{"cpu":"250m","memory":"256Mi"}}` | Container resources. |
| workerDefaults.extraEnv | list | `[]` | Extra environment variables, as in a container spec. |
| workerDefaults.podSecurityContext | object | `{"fsGroup":65532,"runAsGroup":65532,"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod security context. fsGroup makes volumes writable by the nonroot image (uid 65532). |
| workerDefaults.securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}` | Container security context. |
| workerDefaults.nodeSelector | object | `{}` | Node selector. |
| workerDefaults.podAnnotations | object | `{}` | Pod annotations, e.g. prometheus.io/scrape, /port (the admin port) and /path: /metrics. |
| workerDefaults.tolerations | list | `[]` | Tolerations. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
