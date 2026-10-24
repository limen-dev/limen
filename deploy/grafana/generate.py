#!/usr/bin/env python3
"""Generate the Limen Grafana dashboards and alert rules (ADR-0014).

One definition, two targets with identical SQL:
  - Athena over the Glue table in AWS (production)
  - Trino over the same JSONL batches in the dev stack (Athena's engine is Trino)

    python3 deploy/grafana/generate.py      # rewrites the generated files

Generated files are committed; CI checks they're up to date.
"""

import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent

TARGETS = {
    "athena": {
        "ds": {"type": "grafana-athena-datasource", "uid": "limen-athena"},
        "table": "events",  # the data source sets the Glue database
    },
    "trino": {
        "ds": {"type": "trino-datasource", "uid": "limen-trino"},
        "table": "audit.limen.events_raw",
    },
}

# Time filter on the event time, plus a partition filter so Athena scans only
# the days in range. Both data sources expand the $__ macros.
WHERE = (
    "$__timeFilter(from_iso8601_timestamp(\"time\")) "
    "AND dt BETWEEN format_datetime($__timeFrom(), 'yyyy-MM-dd') AND format_datetime($__timeTo(), 'yyyy-MM-dd')"
)

# The "Resource type" dashboard variable (multi-select, defaults to all). Panels
# that group sessions by type filter with {K}; the variable's own query lists
# the types seen in the last 30 days.
KIND_FILTER = "data.kind IN (${kind:singlequote})"
KIND_VARIABLE_SQL = (
    "SELECT DISTINCT data.kind AS kind FROM {T} WHERE kind = 'session.start' AND data.kind IS NOT NULL "
    "AND dt >= format_datetime(current_timestamp - INTERVAL '30' DAY, 'yyyy-MM-dd') ORDER BY 1"
)

# Events are delivered at least once; count distinct event_id, never rows.
PANELS = [
    {
        "title": "Logins and denials",
        "type": "timeseries",
        "w": 12, "h": 8,
        "format": "time_series",
        "sql": """SELECT date_trunc('minute', from_iso8601_timestamp("time")) AS time, kind AS metric, count(DISTINCT event_id) AS value
FROM {T} WHERE {W} AND kind IN ('auth.login', 'auth.denied')
GROUP BY 1, 2 ORDER BY 1""",
    },
    {
        "title": "Active sessions",
        "type": "stat",
        "w": 4, "h": 8,
        "format": "table",
        "description": "Sessions started in the range without a session.end yet.",
        "sql": """SELECT count(*) AS active FROM (
  SELECT session_id FROM {T} WHERE {W} AND kind IN ('session.start', 'session.end') AND session_id IS NOT NULL
  GROUP BY session_id HAVING count_if(kind = 'session.end') = 0
)""",
    },
    {
        "title": "Sessions by actor",
        "type": "timeseries",
        "w": 12, "h": 8,
        "format": "time_series",
        "description": "People and bots (ADR-0019). Events without an actor_type are people's.",
        "sql": """SELECT date_trunc('hour', from_iso8601_timestamp("time")) AS time, coalesce(data.actor_type, 'user') AS metric, count(DISTINCT session_id) AS value
FROM {T} WHERE {W} AND kind = 'session.start'
GROUP BY 1, 2 ORDER BY 1""",
    },
    {
        "title": "Bot sessions by repository",
        "type": "table",
        "w": 12, "h": 8,
        "format": "table",
        "description": "CI jobs, by the repository or project that ran them, with the latest run.",
        "sql": """SELECT coalesce(data.ci.repository, data.ci.project_path, "user") AS source, "user" AS bot, count(DISTINCT session_id) AS sessions,
  max(from_iso8601_timestamp("time")) AS last_session, max_by(data.ci.run_id, from_iso8601_timestamp("time")) AS last_run
FROM {T} WHERE {W} AND kind = 'session.start' AND data.actor_type = 'bot'
GROUP BY 1, 2 ORDER BY sessions DESC LIMIT 100""",
    },
    {
        "title": "Access by resource type",
        "type": "piechart",
        "w": 8, "h": 8,
        "format": "table",
        "sql": """SELECT data.kind AS kind, count(DISTINCT session_id) AS sessions
FROM {T} WHERE {W} AND kind = 'session.start' AND {K}
GROUP BY 1 ORDER BY 2 DESC""",
    },
    {
        "title": "Connections per resource type",
        "type": "timeseries",
        "w": 16, "h": 8,
        "format": "time_series",
        "description": "Sessions started per hour, one line per resource type. Use the Resource type selector to pick which to show.",
        "sql": """SELECT date_trunc('hour', from_iso8601_timestamp("time")) AS time, data.kind AS metric, count(DISTINCT session_id) AS value
FROM {T} WHERE {W} AND kind = 'session.start' AND {K}
GROUP BY 1, 2 ORDER BY 1""",
    },
    {
        "title": "Resource types in use",
        "type": "table",
        "w": 24, "h": 7,
        "format": "table",
        "description": "Per resource type: sessions, distinct people or bots, distinct resources, and the latest connection.",
        "sql": """SELECT data.kind AS kind, count(DISTINCT session_id) AS sessions, count(DISTINCT "user") AS users,
  count(DISTINCT data.resource) AS resources, max(from_iso8601_timestamp("time")) AS last_connection
FROM {T} WHERE {W} AND kind = 'session.start' AND {K}
GROUP BY 1 ORDER BY sessions DESC""",
    },
    {
        "title": "Who accessed what",
        "type": "table",
        "w": 24, "h": 9,
        "format": "table",
        "sql": """SELECT "user", coalesce(data.actor_type, 'user') AS actor, data.resource AS resource, data.login AS login, count(DISTINCT session_id) AS sessions,
  max(from_iso8601_timestamp("time")) AS last_access
FROM {T} WHERE {W} AND kind = 'session.start'
GROUP BY 1, 2, 3, 4 ORDER BY last_access DESC LIMIT 200""",
    },
    {
        "title": "Failed and denied attempts",
        "type": "table",
        "w": 12, "h": 9,
        "format": "table",
        "sql": """SELECT max(from_iso8601_timestamp("time")) AS last_seen, coalesce("user", '(unknown)') AS "user", data.action AS action,
  data.resource AS resource, data.login AS login, data.reason AS reason, count(DISTINCT event_id) AS attempts
FROM {T} WHERE {W} AND kind = 'auth.denied'
GROUP BY 2, 3, 4, 5, 6 ORDER BY last_seen DESC LIMIT 200""",
    },
    {
        "title": "Top users",
        "type": "barchart",
        "w": 12, "h": 9,
        "format": "table",
        "sql": """SELECT "user", count(DISTINCT session_id) AS sessions
FROM {T} WHERE {W} AND kind = 'session.start' AND "user" IS NOT NULL AND coalesce(data.actor_type, 'user') = 'user'
GROUP BY 1 ORDER BY 2 DESC LIMIT 15""",
    },
    {
        "title": "Privileged commands",
        "type": "table",
        "w": 24, "h": 9,
        "format": "table",
        "description": "Commands as root, or using sudo, su, or other privilege-changing tools.",
        "sql": """SELECT from_iso8601_timestamp("time") AS time, "user", data.login AS login, data.resource AS resource, data.command AS command, session_id
FROM {T} WHERE {W} AND kind = 'ssh.exec'
  AND (data.login = 'root' OR regexp_like(data.command, '(^|[;&|[:space:]])(sudo|su|doas|pkexec|chmod|chown|passwd|useradd|usermod|visudo)([[:space:]]|$)'))
ORDER BY 1 DESC LIMIT 200""",
    },
    {
        "title": "Ingestion lag by producer",
        "type": "table",
        "w": 12, "h": 8,
        "format": "table",
        "description": "Seconds since each producer's newest event reached the audit store. A growing value means its events aren't arriving.",
        "sql": """SELECT producer.component AS component, producer.instance_id AS instance,
  to_unixtime(current_timestamp) - to_unixtime(max(from_iso8601_timestamp("time"))) AS lag_seconds
FROM {T} WHERE {W}
GROUP BY 1, 2 ORDER BY lag_seconds DESC""",
    },
    {
        "title": "Missing events (sequence gaps)",
        "type": "table",
        "w": 12, "h": 8,
        "format": "table",
        "description": "Each producer numbers its events. Gaps mean lost events and should always be zero (ADR-0009).",
        "sql": """SELECT producer.instance_id AS instance, min(producer.seq) AS first_seq, max(producer.seq) AS last_seq,
  max(producer.seq) - min(producer.seq) + 1 - count(DISTINCT producer.seq) AS missing
FROM {T} WHERE {W}
GROUP BY 1 ORDER BY missing DESC""",
    },
    {
        "title": "Policy changes",
        "type": "table",
        "w": 24, "h": 7,
        "format": "table",
        "sql": """SELECT from_iso8601_timestamp("time") AS time, "user" AS author, data.version AS version, data.digest AS digest, data.source_ref AS source_ref
FROM {T} WHERE {W} AND kind = 'policy.change'
ORDER BY 1 DESC LIMIT 50""",
    },
]

ALERTS = [
    {
        "uid": "limen-denied-spike",
        "title": "Limen: spike in denied access",
        "sql": "SELECT count(DISTINCT event_id) AS value FROM {T} WHERE kind = 'auth.denied' AND from_iso8601_timestamp(\"time\") > current_timestamp - INTERVAL '10' MINUTE AND dt >= format_datetime(current_timestamp - INTERVAL '1' DAY, 'yyyy-MM-dd')",
        "threshold": 20,
        "summary": "More than 20 denied logins or sessions in 10 minutes.",
    },
    {
        "uid": "limen-sequence-gaps",
        "title": "Limen: audit events missing",
        "sql": "SELECT coalesce(sum(missing), 0) AS value FROM (SELECT max(producer.seq) - min(producer.seq) + 1 - count(DISTINCT producer.seq) AS missing FROM {T} WHERE dt >= format_datetime(current_timestamp - INTERVAL '1' DAY, 'yyyy-MM-dd') GROUP BY producer.instance_id)",
        "threshold": 0,
        "summary": "A producer's audit sequence has gaps: events were lost.",
    },
    {
        "uid": "limen-ingestion-stalled",
        "title": "Limen: audit ingestion stalled",
        "sql": "SELECT coalesce(to_unixtime(current_timestamp) - to_unixtime(max(from_iso8601_timestamp(\"time\"))), 0) AS value FROM {T} WHERE dt >= format_datetime(current_timestamp - INTERVAL '1' DAY, 'yyyy-MM-dd')",
        "threshold": 3600,
        "summary": "No audit event has reached the audit store in over an hour.",
    },
]


def target_query(target, sql, fmt):
    ds = target["ds"]
    if ds["type"] == "grafana-athena-datasource":
        return {
            "datasource": ds,
            "refId": "A",
            "rawSQL": sql,
            "format": 1 if fmt == "table" else 0,
            "connectionArgs": {"catalog": "__default", "database": "__default", "region": "__default", "resultReuseEnabled": False},
        }
    return {"datasource": ds, "refId": "A", "rawSQL": sql, "format": 1 if fmt == "table" else 0}


def kind_variable(target):
    query = target_query(target, KIND_VARIABLE_SQL.replace("{T}", target["table"]), "table")
    del query["refId"]
    return {
        "name": "kind",
        "label": "Resource type",
        "type": "query",
        "datasource": target["ds"],
        "query": query,
        "refresh": 2,
        "multi": True,
        "includeAll": True,
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]},
        "sort": 1,
    }


def dashboard(name):
    target = TARGETS[name]
    panels, x, y, row_h = [], 0, 0, 0
    for i, p in enumerate(PANELS, start=1):
        if x + p["w"] > 24:
            x, y, row_h = 0, y + row_h, 0
        sql = p["sql"].replace("{T}", target["table"]).replace("{W}", WHERE).replace("{K}", KIND_FILTER)
        panel = {
            "id": i,
            "title": p["title"],
            "type": p["type"],
            "datasource": target["ds"],
            "gridPos": {"x": x, "y": y, "w": p["w"], "h": p["h"]},
            "targets": [target_query(target, sql, p["format"])],
            "options": {},
            "fieldConfig": {"defaults": {}, "overrides": []},
        }
        if "description" in p:
            panel["description"] = p["description"]
        panels.append(panel)
        x += p["w"]
        row_h = max(row_h, p["h"])
    return {
        "uid": "limen-audit",
        "title": "Limen audit",
        "tags": ["limen", "audit"],
        "timezone": "utc",
        "schemaVersion": 39,
        "refresh": "1m",
        "templating": {"list": [kind_variable(target)]},
        "time": {"from": "now-24h", "to": "now"},
        "panels": panels,
        "editable": False,
    }


def alert_rules(name):
    target = TARGETS[name]
    rules = []
    for a in ALERTS:
        sql = a["sql"].replace("{T}", target["table"])
        rules.append({
            "uid": f"{a['uid']}-{name}",
            "title": a["title"],
            "condition": "C",
            "for": "5m",
            "noDataState": "OK",
            "execErrState": "Error",
            "annotations": {"summary": a["summary"]},
            "labels": {"service": "limen"},
            "data": [
                {"refId": "A", "datasourceUid": target["ds"]["uid"], "relativeTimeRange": {"from": 86400, "to": 0},
                 "model": dict(target_query(target, sql, "table"), refId="A")},
                {"refId": "B", "datasourceUid": "__expr__", "model": {"type": "reduce", "expression": "A", "reducer": "last", "refId": "B"}},
                {"refId": "C", "datasourceUid": "__expr__", "model": {"type": "threshold", "expression": "B", "refId": "C",
                 "conditions": [{"evaluator": {"type": "gt", "params": [a["threshold"]]}}]}},
            ],
        })
    return {"apiVersion": 1, "groups": [{"orgId": 1, "name": "limen-audit", "folder": "Limen", "interval": "5m", "rules": rules}]}


def queries_for_tests():
    """Panel and alert SQL for the Trino target, with Grafana macros replaced
    by fixed values, so CI and the demo can run every query."""
    t = TARGETS["trino"]["table"]
    def expand(sql):
        return (sql.replace("$__timeFilter(from_iso8601_timestamp(\"time\"))", "from_iso8601_timestamp(\"time\") > current_timestamp - INTERVAL '1' DAY")
                .replace("$__timeFrom()", "(current_timestamp - INTERVAL '1' DAY)")
                .replace("$__timeTo()", "current_timestamp"))
    kinds = KIND_FILTER.replace("${kind:singlequote}", "'postgres', 'redis', 'ssh'")
    out = {p["title"]: expand(p["sql"].replace("{T}", t).replace("{W}", WHERE).replace("{K}", kinds)) for p in PANELS}
    out["Resource type variable"] = KIND_VARIABLE_SQL.replace("{T}", t)
    out.update({a["title"]: a["sql"].replace("{T}", t) for a in ALERTS})
    return out


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main():
    for name in TARGETS:
        write(HERE / "dashboards" / name / "limen-audit.json", dashboard(name))
        write(HERE / "alerting" / name / "limen-audit-rules.json", alert_rules(name))
    write(HERE / "queries.json", queries_for_tests())
    print("generated dashboards and alert rules for", ", ".join(TARGETS))


if __name__ == "__main__":
    main()
