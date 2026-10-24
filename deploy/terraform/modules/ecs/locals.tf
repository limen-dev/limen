locals {
  # Ports per component; see deploy/kubernetes/limen. Workers listen on no
  # service port: they dial out.
  ports = {
    control-plane = { main = 3080, admin = 3081 }
    proxy         = { main = 3443, admin = 3444 }
    worker        = { main = null, admin = 3090 }
  }

  services = {
    for key, s in var.services : key => merge(s, {
      port = local.ports[s.component]
      environment = merge(
        { LIMEN_DATA_DIR = "/var/lib/limen/${s.component}" },
        s.environment,
      )
    })
  }

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
