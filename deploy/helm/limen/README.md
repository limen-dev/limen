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

Values without a default fail the install with a message naming them: `image.tag`, the OIDC issuer and client id, the audit bucket, the four KMS key ids, the proxy `namePrefix` and `dnsNames`, and the worker `namePrefix`, `proxyAddr` and `proxyName`. `ci-values.yaml` is a complete example.

- Each component can be turned off (`proxy.enabled: false`), for example to run workers in another cluster against a proxy elsewhere.
- Grace periods default to the drain times plus margin; the worker template refuses a grace period at or below its drain time.
- On EKS, put the IAM role for KMS and S3 on the control plane's service account with `controlPlane.serviceAccount.annotations`.
- No HorizontalPodAutoscaler is included; the metric source differs between clusters (see the Kubernetes README).
