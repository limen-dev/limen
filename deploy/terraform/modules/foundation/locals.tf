locals {
  # Four keys, one per purpose; each is an ECC_NIST_P256 / SIGN_VERIFY KMS key
  # (design §5, crates/limen-ca/src/kms.rs).
  ca_keys = {
    internal_ca = "mTLS between components"
    user_ca     = "user X.509 certificates"
    ssh_user_ca = "SSH user certificates, trusted by targets"
    ssh_host_ca = "SSH host certificates, trusted by the CLI"
  }

  join_tokens = merge(
    { for k in var.proxy_groups : "proxy-${k}" => { kind = "proxy", group = k } },
    { for k in var.worker_groups : "worker-${k}" => { kind = "worker", group = k } },
  )

  # What a component may be called. A static token is reusable, so it approves a pattern, and
  # the control plane refuses a component that asks for a name the token does not approve.
  name_prefix = coalesce(var.name_prefix, trim(lower(replace(var.name, "/[^a-zA-Z0-9]+/", "-")), "-"))

  # kind:token:group=<key>;limen.io/name=<prefix>-*, comma separated (LIMEN_STATIC_JOIN_TOKENS).
  static_join_tokens = join(",", [
    for k, t in local.join_tokens : "${t.kind}:${random_password.join_token[k].result}:group=${t.group};limen.io/name=${local.name_prefix}-*"
  ])

  eks = var.eks_oidc_provider_arn != null
}
