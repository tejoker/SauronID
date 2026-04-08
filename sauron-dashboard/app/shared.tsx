"use client";

/* ── API helpers ─────────────────────────────────────────────────────────── */

const DASH_API =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002")
    : "http://localhost:8002";

type AdminStats = {
  total_users: number;
  total_clients: number;
  total_api_calls: number;
  total_kyc_retrievals: number;
  total_agent_calls: number;
  total_tokens_b_issued?: number;
  total_tokens_b_spent?: number;
  exchange_rate?: number;
};

type AdminClient = {
  name: string;
  client_type: string;
  tokens_b?: number;
};

type AdminRequest = {
  id: number;
  timestamp: number;
  action_type: string;
  status: string;
  detail: string;
};

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function monthLabel(unixTs: number): string {
  const d = new Date(unixTs * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

function dayLabel(unixTs: number): string {
  const d = new Date(unixTs * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

async function fallbackFromCore(path: string): Promise<unknown> {
  const [stats, clients, requests] = await Promise.all([
    fetchJson<AdminStats>("/api/admin/stats"),
    fetchJson<AdminClient[]>("/api/admin/clients").catch(() => []),
    fetchJson<AdminRequest[]>("/api/admin/requests").catch(() => []),
  ]);

  if (path === "overview") {
    const byDay = new Map<string, { a: number; b: number }>();
    for (const r of requests) {
      const key = dayLabel(r.timestamp);
      const prev = byDay.get(key) ?? { a: 0, b: 0 };
      if (r.action_type === "KYC_RETRIEVE") prev.a += 1;
      if (r.action_type === "BUY_TOKENS") prev.b += 1;
      byDay.set(key, prev);
    }
    const sortedDays = Array.from(byDay.keys()).sort();
    const last90 = sortedDays.slice(-90);
    return {
      kpis: {
        total_full_kyc: stats.total_kyc_retrievals ?? 0,
        total_reduced: stats.total_api_calls ?? 0,
        active_clients: stats.total_clients ?? clients.length,
        kyc_revenue_usd: Number((stats.total_kyc_retrievals ?? 0) * 0.35),
        credit_a_earned: stats.total_api_calls ?? 0,
        credit_b_purchased: stats.total_tokens_b_issued ?? 0,
        query_revenue_usd: Number((stats.total_tokens_b_spent ?? 0) * 0.1),
        failure_rate: 0,
      },
      daily: {
        dates: last90,
        credit_a: last90.map((d) => byDay.get(d)?.a ?? 0),
        credit_b: last90.map((d) => byDay.get(d)?.b ?? 0),
      },
      rings: {
        labels: ["users", "clients", "agents"],
        names: ["User ring", "Client ring", "Agent ring"],
        counts: [
          stats.total_users ?? 0,
          stats.total_clients ?? clients.length,
          stats.total_agent_calls ?? 0,
        ],
      },
    };
  }

  if (path === "anomalies") {
    const failEvents = requests
      .filter((r) => r.status !== "OK")
      .map((r) => ({
        client_id: 0,
        date: new Date(r.timestamp * 1000).toISOString().slice(0, 10),
        anomaly_type: r.action_type,
        severity: r.status === "FAIL" ? "high" : "medium",
        message: r.detail || "request anomaly",
        name: "core",
        type: "system",
      }));
    const byTypeMap = new Map<string, number>();
    const bySevMap = new Map<string, number>();
    const byMonthMap = new Map<string, number>();
    for (const e of failEvents) {
      byTypeMap.set(e.anomaly_type, (byTypeMap.get(e.anomaly_type) ?? 0) + 1);
      bySevMap.set(e.severity, (bySevMap.get(e.severity) ?? 0) + 1);
    }
    for (const r of requests) {
      const m = monthLabel(r.timestamp);
      byMonthMap.set(m, (byMonthMap.get(m) ?? 0) + (r.status !== "OK" ? 1 : 0));
    }
    const months = Array.from(byMonthMap.keys()).sort().slice(-12);
    return {
      events: failEvents,
      by_type: Array.from(byTypeMap.entries()).map(([anomaly_type, count]) => ({ anomaly_type, count })),
      by_severity: Array.from(bySevMap.entries()).map(([severity, count]) => ({ severity, count })),
      monthly: {
        months,
        counts: months.map((m) => byMonthMap.get(m) ?? 0),
      },
    };
  }

  if (path === "insights") {
    return {
      avg_churn_risk: 0,
      avg_trust_score: 0,
      ml_anomalies_detected: 0,
      at_risk_clients: [],
    };
  }

  if (path === "insights/forecast") return { actual: [], forecast: [] };
  if (path === "insights/load") return { historical: [], forecast: [] };
  if (path === "insights/elasticity") return { metrics: [] };
  if (path === "insights/anomalies-ml") return { events: [], total: 0, precision_proxy: null };
  if (path === "insights/clients") {
    return {
      clients: clients.map((c, i) => ({
        client_id: i + 1,
        name: c.name,
        type: c.client_type,
        sector: "identity",
        health_score: 92,
        trust_score: 95,
        churn_risk: 0.08,
        runway_days: 365,
        burn_rate: 0,
        current_balance: c.tokens_b ?? 0,
      })),
    };
  }

  if (path === "gdpr/stats") {
    return {
      total_users: stats.total_users ?? 0,
      eu_eea_scope: stats.total_users ?? 0,
      non_eu_total: 0,
      active_users: stats.total_users ?? 0,
      anonymized_total: 0,
      pending_purge: 0,
      retention_days: 365,
      cutoff_date: new Date().toISOString().slice(0, 10),
      last_run_date: null,
      last_run_purged: 0,
      monthly_history: [],
      run_log: [],
    };
  }

  if (path === "gdpr/purge") {
    return { purged: 0, message: "Purge simulator only in fallback mode" };
  }

  if (path === "pipeline-stats") {
    return {
      live: false,
      throughput: 0,
      avg_latency_ms: 0,
      uptime_pct: 100,
      fraud_detected: 0,
      total_events: requests.length,
      latency: [
        { service: "core", ms: 20 },
        { service: "db", ms: 8 },
        { service: "issuer", ms: 32 },
      ],
      resources: [
        { name: "core", cpu_pct: 12, mem_mb: 220, status: "healthy" },
        { name: "dashboard", cpu_pct: 6, mem_mb: 140, status: "healthy" },
      ],
    };
  }

  throw new Error(`No fallback mapping for '${path}'`);
}

export async function sauronFetch<T>(path: string): Promise<T> {
  const url = `${DASH_API}/api/${path.replace(/^\//, "")}`;
  try {
    return await fetchJson<T>(url);
  } catch {
    return (await fallbackFromCore(path)) as T;
  }
}

/* ── KPI Card ────────────────────────────────────────────────────────────── */
export function Kpi({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="bg-white rounded-2xl p-4 flex flex-col gap-1" style={{boxShadow:"0 1px 3px rgba(0,0,0,0.07),0 1px 2px rgba(0,0,0,0.04)"}}>
      <span className="text-[11px] font-medium text-[#8e8e93] uppercase tracking-wide">
        {label}
      </span>
      <span
        className={`text-[28px] font-bold tabular-nums leading-none ${accent ?? "text-[#1c1c1e]"}`}
      >
        {value}
      </span>
      {sub && (
        <span className="text-xs text-[#8e8e93]">{sub}</span>
      )}
    </div>
  );
}

/* ── Section Header ──────────────────────────────────────────────────────── */
export function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-3">
      <h2 className="text-sm font-semibold text-neutral-700 uppercase tracking-wider">
        {title}
      </h2>
      {children}
    </section>
  );
}

/* ── Card ─────────────────────────────────────────────────────────────────── */
export function Card({
  title,
  children,
  className,
}: {
  title?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-white rounded-2xl p-5 ${className ?? ""}`}
      style={{boxShadow:"0 1px 3px rgba(0,0,0,0.07),0 1px 2px rgba(0,0,0,0.04)"}}
    >
      {title && (
        <h3 className="text-[11px] font-semibold text-[#8e8e93] uppercase tracking-wider mb-4">
          {title}
        </h3>
      )}
      {children}
    </div>
  );
}

/* ── Spinner ──────────────────────────────────────────────────────────────── */
export function Spinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="w-8 h-8 border-[3px] border-[#007AFF] border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

/* ── Format helpers ───────────────────────────────────────────────────────── */
export function fmtNum(n: number | null | undefined, decimals = 0): string {
  if (n == null) return "\u2014";
  return n.toLocaleString("en-US", { maximumFractionDigits: decimals });
}

export function fmtPct(n: number | null | undefined): string {
  if (n == null) return "\u2014";
  return `${n.toFixed(1)}%`;
}

export function fmtUsd(n: number | null | undefined): string {
  if (n == null) return "\u2014";
  return `$${fmtNum(n, 2)}`;
}
