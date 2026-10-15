# The event table. Batches are gzipped JSON Lines under
# events/dt=YYYY-MM-DD/hour=HH/; partition projection means no crawler and
# no partition maintenance. Keep the columns in step with the local Trino
# table (deploy/compose/trino/init.sql). Fields not listed are ignored.

locals {
  data_struct = join(",", [
    "resource:string", "login:string", "command:string", "reason:string", "action:string",
    "kind:string", "worker_id:string", "proxy_id:string", "client_addr:string",
    "duration_ms:bigint", "bytes_in:bigint", "bytes_out:bigint",
    "recording_uri:string", "sha256:string", "recording_sha256:string", "bytes:bigint",
    "login_id:string", "flow:string", "cert_serial:string", "expires_at:bigint",
    "roles:array<string>", "groups:array<string>",
    "version:bigint", "digest:string", "source_ref:string", "component_id:string",
    # Machine identities (ADR-0019): who the actor was, and the CI run behind a bot.
    "actor_type:string", "method:string", "bot:string",
    "ci:struct<provider:string,repository:string,repository_owner:string,project_path:string,namespace_path:string,ref:string,ref_type:string,ref_protected:string,environment:string,workflow:string,job_workflow_ref:string,run_id:string,run_attempt:string,pipeline_id:string,pipeline_source:string,job_id:string,event_name:string,runner_environment:string,sha:string,actor:string,user_login:string,iss:string,sub:string>",
  ])
  columns = [
    { name = "schema_version", type = "int" },
    { name = "event_id", type = "string" },
    { name = "kind", type = "string" },
    { name = "time", type = "string" },
    { name = "producer", type = "struct<component:string,instance_id:string,seq:bigint>" },
    { name = "user", type = "string" },
    { name = "session_id", type = "string" },
    { name = "data", type = "struct<${local.data_struct}>" },
  ]
}

resource "aws_glue_catalog_database" "audit" {
  name        = replace("${var.name}_audit", "-", "_")
  description = "Limen audit events"
}

resource "aws_glue_catalog_table" "events" {
  database_name = aws_glue_catalog_database.audit.name
  name          = "events"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"              = "json"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "2026-01-01,NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "projection.hour.type"        = "enum"
    "projection.hour.values"      = join(",", [for h in range(24) : format("%02d", h)])
    "storage.location.template"   = "s3://${aws_s3_bucket.audit.bucket}/events/dt=$${dt}/hour=$${hour}/"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }
  partition_keys {
    name = "hour"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.audit.bucket}/events/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "case.insensitive" = "false"
      }
    }

    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}
