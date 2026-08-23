-- S8 extension: persistent per-cohort per-metric ε ledger.
--
-- Closes the documented "No inter-period ε budget tracking" gap. Each
-- publication checks the cohort's remaining ε budget against a lifetime
-- cap for the current regulatory cycle and refuses publication when the
-- budget is exhausted. Operators rotate (reset) the budget per cycle
-- through POST /v1/cohort/:id/budget/rotate.
--
-- Composition: basic (sequential) — ε's add. Advanced composition would
-- be looser but riskier without RDP tracking; see core/src/dp/ledger.rs
-- documentation and docs/architecture/privacy-model.md.

BEGIN;

CREATE TABLE IF NOT EXISTS dp_budget_ledger (
    cohort_id      TEXT    NOT NULL,
    metric_id      TEXT    NOT NULL,
    cycle_start    BIGINT  NOT NULL,
    epsilon_spent  DOUBLE PRECISION NOT NULL DEFAULT 0,
    delta_spent    DOUBLE PRECISION NOT NULL DEFAULT 0,
    epsilon_cap    DOUBLE PRECISION NOT NULL,
    delta_cap      DOUBLE PRECISION NOT NULL,
    last_published BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (cohort_id, metric_id, cycle_start)
);

CREATE INDEX IF NOT EXISTS idx_dp_budget_cohort
    ON dp_budget_ledger(cohort_id, cycle_start);

CREATE TABLE IF NOT EXISTS dp_budget_publications (
    publication_id TEXT    PRIMARY KEY,
    cohort_id      TEXT    NOT NULL,
    metric_id      TEXT    NOT NULL,
    cycle_start    BIGINT  NOT NULL,
    epsilon        DOUBLE PRECISION NOT NULL,
    delta          DOUBLE PRECISION NOT NULL,
    noise_scale    DOUBLE PRECISION NOT NULL,
    published_at   BIGINT  NOT NULL,
    FOREIGN KEY (cohort_id, metric_id, cycle_start)
        REFERENCES dp_budget_ledger(cohort_id, metric_id, cycle_start)
);

CREATE INDEX IF NOT EXISTS idx_dp_pub_cohort
    ON dp_budget_publications(cohort_id, cycle_start);

-- Operator-managed cohort registry for DP-published cross-tenant benchmarks.
-- Global (NOT tenant-scoped) — see docs/architecture/privacy-model.md "Publication pipeline".
-- Created here because 0009 is the first migration to reference it; the ε ledger
-- above extends it with per-cycle caps below.
CREATE TABLE IF NOT EXISTS cohort_definitions (
    cohort_id              TEXT PRIMARY KEY,
    label                  TEXT    NOT NULL,
    vendor                 TEXT,
    sector                 TEXT,
    tenant_ids_json        TEXT    NOT NULL,
    k_anonymity_threshold  INTEGER NOT NULL DEFAULT 5,
    epsilon_per_metric     DOUBLE PRECISION NOT NULL,
    delta                  DOUBLE PRECISION NOT NULL,
    created_at             BIGINT  NOT NULL,
    updated_at             BIGINT  NOT NULL
);

-- Extend cohort_definitions with optional cycle defaults. All nullable;
-- existing rows keep working untouched. The ledger module falls back to
-- 90-day cycles and epsilon_per_metric * 4 cap when these are NULL.
ALTER TABLE cohort_definitions
    ADD COLUMN IF NOT EXISTS cycle_seconds         BIGINT;
ALTER TABLE cohort_definitions
    ADD COLUMN IF NOT EXISTS epsilon_cap_per_cycle DOUBLE PRECISION;
ALTER TABLE cohort_definitions
    ADD COLUMN IF NOT EXISTS delta_cap_per_cycle   DOUBLE PRECISION;

COMMIT;
