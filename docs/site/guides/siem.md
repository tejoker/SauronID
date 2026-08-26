# SIEM integration

SauronID ships its audit trail into your SIEM as configuration, not as an
integration project. Core never pushes anywhere; it exposes three
tamper-evident, scrape-friendly surfaces:

- an append-only JSONL file (`SAURON_AUDIT_LOG_PATH`) for Splunk, Filebeat,
  Vector, or any file shipper;
- a pull API, `GET /v1/admin/audit` (admin-gated, tenant-scoped), for
  reconciliation and backfill;
- Prometheus `/metrics` — alert on `audit_sink_failure_count`.

Every event also lands in an HMAC hash-chained table, so the SIEM copy can
be re-verified against the chain at any time.

Core never pushes because a push target is a credential the gateway would have
to hold and an outbound path an agent could try to reach. Point your existing
shipper at the JSONL file, or poll the admin API.
