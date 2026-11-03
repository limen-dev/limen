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
        # Drain inside the stop timeout (docs/runbooks/scale-out.md): a copy that
        # outlives it is killed mid-drain. Control planes and proxies drain for
        # at most 20 s (the default), workers 30 s less than the timeout.
        g.component == "worker" ? { LIMEN_DRAIN_TIMEOUT_SECS = tostring(max(g.stop_timeout - 30, 1)) } : {},
        g.component == "proxy" ? { LIMEN_DRAIN_TIMEOUT_SECS = tostring(min(20, max(g.stop_timeout - 10, 1))) } : {},
        g.component == "control-plane" ? { LIMEN_DRAIN_TIMEOUT = "${min(20, max(g.stop_timeout - 10, 1))}s" } : {},
        # Neither a Fargate task nor an Auto Scaling instance keeps its disk, so
        # a replica hands what it has not shipped to a peer instead of resuming it.
        g.component == "control-plane" ? { LIMEN_SPOOL_MODE = g.spool_mode } : {},
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

  # The admin port (/readyz, /metrics) has no authentication: only the sources
  # named in admin_ingress_cidrs reach it (the security group allows no one else).
  admin_ingress_rules = {
    for key, g in local.groups : key => {
      for i, cidr in g.admin_ingress_cidrs : "admin-cidr-${i}" => {
        cidr_ipv4 = cidr
      }
    }
  }

  # Docker publishes both ports on the host; the security group decides who reaches them.
  publish = {
    for key, g in local.groups : key => join(" ", concat(
      g.port.main == null ? [] : ["-p ${g.port.main}:${g.port.main}"],
      ["-p ${g.port.admin}:${g.port.admin}"],
    ))
  }
}
