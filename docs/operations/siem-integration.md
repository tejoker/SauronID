# SIEM integration

SauronID's audit trail is designed to be shipped into your SIEM as
configuration, not as an integration project. The core never pushes to a
SIEM itself; it exposes three tamper-evident, scrape-friendly surfaces and
your existing log shipper does the rest.

## The three surfaces

| Surface | What it is | How to consume |
|---|---|---|
| Append-only JSONL file | Every security audit event, one JSON object per line | Set `SAURON_AUDIT_LOG_PATH=/var/log/sauronid/audit.jsonl` and point any shipper at it |
| Query API | `GET /v1/admin/audit` (admin-gated, tenant-scoped) | Poll for reconciliation or backfill |
| Prometheus metrics | `GET /metrics` | Scrape; alert on `audit_sink_failure_count` |

Events are simultaneously written to a hash-chained database table (HMAC
chain keyed by `SAURON_AUDIT_HMAC_KEY`), so a SIEM copy can always be
re-verified against the chain. If the file sink ever drops an event,
`audit_sink_failure_count` increments — alert on it.

## Splunk (universal forwarder)

```ini
# inputs.conf
[monitor:///var/log/sauronid/audit.jsonl]
sourcetype = _json
index = sauronid
```

## Elastic (Filebeat)

```yaml
filebeat.inputs:
  - type: filestream
    paths: ["/var/log/sauronid/audit.jsonl"]
    parsers:
      - ndjson:
          target: sauronid
```

## Vector (any sink: Datadog, S3, Loki, Kafka, ...)

```toml
[sources.sauronid_audit]
type = "file"
include = ["/var/log/sauronid/audit.jsonl"]

[transforms.parse]
type = "remap"
inputs = ["sauronid_audit"]
source = ". = parse_json!(.message)"

[sinks.your_siem]
type = "datadog_logs"   # or aws_s3, loki, kafka, splunk_hec, ...
inputs = ["parse"]
```

## Polling the query API

For shippers that prefer HTTP pull, or for backfill after an outage:

```bash
curl -s "$SAURON_CORE_URL/v1/admin/audit?since=2026-07-01T00:00:00Z" \
  -H "x-admin-key: $SAURON_ADMIN_KEY" \
  -H "x-sauron-tenant-id: $TENANT_ID"
```

Results are scoped to the calling operator's tenant.

## Verifying integrity after ingestion

Each event carries its position in the HMAC hash chain. To confirm your
SIEM copy has not been altered (and that no events were dropped between
SauronID and the SIEM), re-query `/v1/admin/audit` for the same window and
compare chain heads. A broken chain means tampering or loss; the chain key
never leaves the core.

## Why pull, not push

A push integration makes the authorization boundary depend on the
availability and credentials of an external log endpoint, and a compromised
core could be induced to exfiltrate through it. File-plus-scrape keeps the
core's egress surface at zero while giving the SIEM an identical event
stream. See [`threat-model.md`](../security/threat-model.md) for the full rationale.
