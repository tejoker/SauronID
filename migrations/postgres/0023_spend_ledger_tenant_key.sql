-- Put tenant_id in spend_ledger's primary key.
--
-- 0004_multi_tenant.sql added tenant_id as a COLUMN and an index, but left the
-- primary key as (policy_id, agent_id, period_start). Repo's upsert conflict
-- target matched that key, so it was tenant-blind: two tenants recording spend
-- against the same logical (agent, policy, period) collapsed into ONE row, owned
-- by whichever wrote first.
--
-- Consequences, both bad, because get_spend_total is what the `budget` and
-- `daily_budget` invariants consult:
--
--   * the non-owning tenant read 0, so its spend cap never tripped — a budget
--     bypass;
--   * the owning tenant absorbed the other's spend and its agents were denied
--     for money they never spent — cross-tenant denial of service.
--
-- Reproduced by redteam/src/scenarios/tenant-spend-ledger-race.ts: two tenants,
-- ten spends each on one (agent_id, policy_id), produced 20 correctly-split
-- spend_log rows and a SINGLE spend_ledger row holding 1010.0 under tenant A.
-- docs/multi-tenancy-audit.md carries the full write-up.
--
-- NON-DESTRUCTIVE. No row is deleted or merged: every existing row keeps its own
-- tenant_id and total. What this cannot do is un-merge a total that already
-- absorbed another tenant's spend, because that was never recorded separately in
-- this table. Such a row stays with the tenant that owned it — over-counted
-- rather than lost, which is the conservative direction for a cap. The victim
-- tenant begins accumulating its own row correctly from here.
--
-- An operator who needs the historical split can rebuild it from spend_log,
-- which was tenant-correct throughout:
--
--   SELECT tenant_id, policy_id, agent_id, SUM(amount_usd)
--   FROM spend_log GROUP BY tenant_id, policy_id, agent_id;

ALTER TABLE spend_ledger
    ALTER COLUMN tenant_id SET DEFAULT 'default';

UPDATE spend_ledger SET tenant_id = 'default' WHERE tenant_id IS NULL;

ALTER TABLE spend_ledger
    ALTER COLUMN tenant_id SET NOT NULL;

-- Idempotent: the constraint name is Postgres's default for this table.
ALTER TABLE spend_ledger DROP CONSTRAINT IF EXISTS spend_ledger_pkey;

ALTER TABLE spend_ledger
    ADD CONSTRAINT spend_ledger_pkey
    PRIMARY KEY (tenant_id, policy_id, agent_id, period_start);

CREATE INDEX IF NOT EXISTS idx_spend_ledger_tenant
    ON spend_ledger (tenant_id, policy_id, agent_id);
