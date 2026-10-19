-- The audit table over the S3 batches (ADR-0014), matching the Glue table
-- Terraform creates for Athena (deploy/terraform/modules/audit). Fields the
-- table doesn't list are ignored (for a bot's CI run, that includes claims a generic
-- OIDC rule names); add them here and in Terraform together.
CREATE SCHEMA IF NOT EXISTS audit.limen;

CREATE TABLE IF NOT EXISTS audit.limen.events_raw (
  schema_version integer,
  event_id varchar,
  kind varchar,
  "time" varchar,
  producer row(component varchar, instance_id varchar, seq bigint),
  "user" varchar,
  session_id varchar,
  data row(
    resource varchar, login varchar, command varchar, reason varchar, action varchar,
    kind varchar, worker_id varchar, proxy_id varchar, client_addr varchar,
    duration_ms bigint, bytes_in bigint, bytes_out bigint,
    recording_uri varchar, sha256 varchar, recording_sha256 varchar, bytes bigint,
    login_id varchar, flow varchar, cert_serial varchar, expires_at bigint,
    roles array(varchar), groups array(varchar),
    version bigint, digest varchar, source_ref varchar, component_id varchar,
    actor_type varchar, method varchar, bot varchar,
    ci row(
      provider varchar,
      repository varchar,
      repository_owner varchar,
      project_path varchar,
      namespace_path varchar,
      ref varchar,
      ref_type varchar,
      ref_protected varchar,
      environment varchar,
      workflow varchar,
      job_workflow_ref varchar,
      run_id varchar,
      run_attempt varchar,
      pipeline_id varchar,
      pipeline_source varchar,
      job_id varchar,
      event_name varchar,
      runner_environment varchar,
      sha varchar,
      actor varchar,
      user_login varchar,
      iss varchar,
      sub varchar
    )
  ),
  dt varchar,
  hour varchar
)
WITH (
  format = 'JSON',
  partitioned_by = ARRAY['dt', 'hour'],
  external_location = 's3://limen-audit/events'
);
