locals {
  # Ports per component; see deploy/kubernetes/limen. Workers listen on no
  # service port: they dial out.
  ports = {
    control-plane = { main = 3080, admin = 3081 }
    proxy         = { main = 3443, admin = 3444 }
    worker        = { main = null, admin = 3090 }
  }

  # Where each component finds the internal CA certificate. The control plane
  # exports it to ca-public; proxies and workers read it from ca-trust.
  ca_export_dir = "/var/lib/limen/ca-public"
  ca_trust_dir  = "/etc/limen-ca"

  services = {
    for key, s in var.services : key => merge(s, {
      port      = local.ports[s.component]
      publishes = s.component == "control-plane" && var.internal_ca != null
      consumes  = s.component != "control-plane" && var.internal_ca != null
      environment = merge(
        { LIMEN_DATA_DIR = "/var/lib/limen/${s.component}" },
        s.component == "control-plane" ? { LIMEN_CA_EXPORT_DIR = local.ca_export_dir } : {},
        s.component != "control-plane" && var.internal_ca != null ? { LIMEN_CA_FILE = "${local.ca_trust_dir}/internal-ca.pem" } : {},
        s.environment,
      )
    })
  }

  # Publishes the exported certificate to the secret, again whenever it changes.
  ca_publisher_script = <<-EOT
    set -eu
    last=""
    while true; do
      f=${local.ca_export_dir}/internal-ca.pem
      if [ -s "$f" ]; then
        sum=$(cksum < "$f")
        if [ "$sum" != "$last" ]; then
          aws secretsmanager put-secret-value --secret-id "$CA_SECRET_ID" --secret-string "file://$f" > /dev/null && last="$sum"
        fi
      fi
      sleep 30
    done
  EOT

  # Fails (so ECS retries the task) until the control plane has published.
  ca_writer_script = <<-EOT
    set -eu
    case "$CA_PEM" in
      "-----BEGIN"*) ;;
      *) echo "internal CA not published yet" >&2; exit 1 ;;
    esac
    printf '%s\n' "$CA_PEM" > ${local.ca_trust_dir}/internal-ca.pem
  EOT

  # One ingress rule per allowed source, only on components with a service port.
  ingress_rules = {
    for key, s in local.services : key => merge(
      {
        for i, cidr in s.ingress_cidrs : "cidr-${i}" => {
          cidr_ipv4 = cidr
        }
      },
      {
        for i, sg in s.ingress_security_group_ids : "sg-${i}" => {
          referenced_security_group_id = sg
        }
      },
    ) if s.port.main != null
  }
}
