locals {
  # Ports per component; see deploy/kubernetes/limen. Workers listen on no
  # service port: they dial out.
  ports = {
    control-plane = { main = 3080, admin = 3081 }
    proxy         = { main = 3443, admin = 3444 }
    worker        = { main = null, admin = 3090 }
  }

  groups = {
    for key, g in var.groups : key => merge(g, {
      port      = local.ports[g.component]
      publishes = g.component == "control-plane" && var.internal_ca != null
      consumes  = g.component != "control-plane" && var.internal_ca != null
      environment = merge(
        { LIMEN_DATA_DIR = "/var/lib/limen/${g.component}" },
        g.component == "control-plane" ? { LIMEN_CA_EXPORT_DIR = "/var/lib/limen/ca-public" } : {},
        g.component != "control-plane" && var.internal_ca != null ? { LIMEN_CA_FILE = "/etc/limen/internal-ca.pem" } : {},
        g.environment,
      )
    })
  }

  ingress_rules = {
    for key, g in local.groups : key => merge(
      {
        for i, cidr in g.ingress_cidrs : "cidr-${i}" => {
          cidr_ipv4 = cidr
        }
      },
      {
        for i, sg in g.ingress_security_group_ids : "sg-${i}" => {
          referenced_security_group_id = sg
        }
      },
    ) if g.port.main != null
  }

  # Docker publishes the service port on the host; the admin port stays on the
  # loopback interface for health checks.
  publish = {
    for key, g in local.groups : key => join(" ", concat(
      g.port.main == null ? [] : ["-p ${g.port.main}:${g.port.main}"],
      ["-p 127.0.0.1:${g.port.admin}:${g.port.admin}"],
    ))
  }
}
