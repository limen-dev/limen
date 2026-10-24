# Limen Helm chart

Runs the control plane (StatefulSet, headless Service, PodDisruptionBudget), the proxy (Deployment, `LoadBalancer` Service) and the workers (Deployment). It templates the manifests in [`deploy/kubernetes/limen`](../../kubernetes/limen/README.md); read that README for why each setting looks the way it does.

**Unverified:** the chart passes `helm lint` and `helm template` (CI runs both) but was never installed on a cluster. Issue #85 tracks the real-cluster test.

```sh
kubectl create secret generic limen-database --from-literal=url='postgres://...'
kubectl create secret generic limen-proxy-join  --from-literal=token=...
kubectl create secret generic limen-worker-join --from-literal=token=...
kubectl create configmap limen-internal-ca --from-file=internal-ca.pem

helm install limen deploy/helm/limen -f my-values.yaml
```

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

Values without a default fail the install with a message naming them: `image.tag`, the OIDC issuer and client id, the audit bucket and the four KMS key ids (in `controlPlaneDefaults`), and the `namePrefix` and `dnsNames` of proxies and the `namePrefix` of workers. `ci-values.yaml` is a complete example with three worker groups and two proxy groups.

- Grace periods default to the drain times plus margin; a worker group refuses a grace period at or below its drain time.
- On EKS, put the IAM role for KMS and S3 on a control plane's service account with `serviceAccount.annotations`.
- No HorizontalPodAutoscaler is included; the metric source differs between clusters (see the Kubernetes README).
