"use client";

import { useEffect, useState } from "react";
import "./chartSetup";
import { Line, Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtPct, fmtUsd } from "./shared";
import { useDash } from "./context/DashContext";

interface OverviewData {
  kpis: Record<string, number>;
  daily: { dates: string[]; credit_a: number[]; credit_b: number[] };
  rings: { labels: string[]; names: string[]; counts: number[] };
}

interface AnomalyEvent {
  anomaly_type: string;
  severity: string;
  description?: string;
  date?: string;
  name?: string;
}

interface InsightsData {
  avg_churn_risk: number;
  avg_trust_score: number;
  ml_anomalies_detected: number;
  at_risk_clients: { client_id: number; name: string; churn_risk: number }[];
}

interface GdprData {
  total_users: number;
  eu_eea_scope: number;
  pending_purge: number;
}

interface PipelineData {
  total_events?: number;
  throughput?: number;
  throughput_eps?: number;
  total_fraud?: number;
  total_block?: number;
  fraud_detected?: number;
  live?: boolean;
}

const CHART_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: {
    x: { grid: { display: false } },
    y: { beginAtZero: true, grid: { color: "#f3f4f6" } },
  },
};

export default function OverviewPage() {
  const { stats, offline } = useDash();
  const [data, setData] = useState<OverviewData | null>(null);
  const [anomalies, setAnomalies] = useState<AnomalyEvent[]>([]);
  const [insights, setInsights] = useState<InsightsData | null>(null);
  const [gdpr, setGdpr] = useState<GdprData | null>(null);
  const [pipeline, setPipeline] = useState<PipelineData | null>(null);

  useEffect(() => {
    Promise.all([
      sauronFetch<OverviewData>("overview").catch(() => null),
      sauronFetch<{ events: AnomalyEvent[] }>("anomalies").catch(() => ({ events: [] })),
      sauronFetch<InsightsData>("insights").catch(() => null),
      sauronFetch<GdprData>("gdpr/stats").catch(() => null),
      sauronFetch<PipelineData>("pipeline-stats").catch(() => null),
    ]).then(([o, a, i, g, p]) => {
      setData(o);
      setAnomalies(a.events?.slice(0, 8) ?? []);
      setInsights(i);
      setGdpr(g);
      setPipeline(p);
    });
  }, []);

  if (!data && !stats && !offline) return <Spinner />;
  if (!data && !stats && offline) {
    return (
      <div className="space-y-4 max-w-[900px]">
        <h1 className="text-lg font-bold text-neutral-900">Platform Overview</h1>
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">
          Backend offline. Start core API on port 3001, then refresh dashboard.
        </div>
      </div>
    );
  }

  const k = data?.kpis ?? {};

  return (
    <div className="space-y-6 max-w-[1200px]">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-neutral-900">Platform Overview</h1>
        {offline && <span className="text-xs px-2.5 py-1 rounded-full bg-red-50 text-red-600 font-medium">Backend offline</span>}
      </div>

      {/* KPI grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <Kpi label="KYC Completions" value={fmtNum(k.total_full_kyc ?? stats?.total_users)} />
        <Kpi label="Attribute Queries" value={fmtNum(k.total_reduced)} />
        <Kpi label="Active Clients" value={fmtNum(k.active_clients ?? stats?.total_clients)} />
        <Kpi label="KYC Revenue" value={fmtUsd(k.kyc_revenue_usd)} accent="text-green-600" />
        <Kpi label="Credit A Earned" value={fmtNum(k.credit_a_earned)} accent="text-blue-600" />
        <Kpi label="Credit B Purchased" value={fmtNum(k.credit_b_purchased)} accent="text-orange-500" />
        <Kpi label="Query Revenue" value={fmtUsd(k.query_revenue_usd)} accent="text-green-600" />
        <Kpi label="Failure Rate" value={fmtPct(k.failure_rate)} accent={(k.failure_rate ?? 0) > 5 ? "text-red-600" : "text-neutral-900"} />
        <Kpi label="Exchange Rate" value={stats ? `1:${stats.exchange_rate}` : "\u2014"} />
        {gdpr && <Kpi label="GDPR Pending" value={fmtNum(gdpr.pending_purge)} accent={gdpr.pending_purge > 0 ? "text-amber-600" : "text-green-600"} />}
        {pipeline && <Kpi label="Pipeline EPS" value={(pipeline.throughput ?? pipeline.throughput_eps ?? 0).toFixed(1)} sub={pipeline.total_events != null ? `${fmtNum(pipeline.total_events)} events` : undefined} />}
      </div>

      {/* Charts row */}
      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card title="Daily Credit Activity (90 days)">
            <div className="h-60">
              <Line
                data={{
                  labels: data.daily.dates,
                  datasets: [
                    { label: "Credit A", data: data.daily.credit_a, borderColor: "#3b82f6", backgroundColor: "rgba(59,130,246,0.08)", fill: true, tension: 0.3, pointRadius: 0 },
                    { label: "Credit B", data: data.daily.credit_b, borderColor: "#f97316", backgroundColor: "rgba(249,115,22,0.08)", fill: true, tension: 0.3, pointRadius: 0 },
                  ],
                }}
                options={{ ...CHART_OPTS, plugins: { legend: { display: true, position: "top" as const, labels: { boxWidth: 10, font: { size: 11 } } } } }}
              />
            </div>
          </Card>

          <Card title="Ring Sizes">
            <div className="h-60">
              <Bar
                data={{
                  labels: data.rings.names,
                  datasets: [{ data: data.rings.counts, backgroundColor: "#6366f1", borderRadius: 4 }],
                }}
                options={CHART_OPTS}
              />
            </div>
          </Card>
        </div>
      )}

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Recent Anomalies">
          {anomalies.length === 0 ? (
            <p className="text-sm text-neutral-400">No recent anomalies</p>
          ) : (
            <div className="space-y-1.5 max-h-60 overflow-auto">
              {anomalies.map((a, i) => (
                <div key={i} className="flex items-center gap-2 text-xs py-1.5 border-b border-neutral-100 last:border-0">
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${a.severity === "high" ? "bg-red-500" : a.severity === "medium" ? "bg-amber-500" : "bg-blue-400"}`} />
                  <span className="font-mono text-neutral-500">{a.anomaly_type}</span>
                  {a.name && <span className="text-neutral-400">{a.name}</span>}
                  <span className="ml-auto text-neutral-300 tabular-nums">{a.date?.slice(0, 10)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="At-Risk Clients">
          {insights && insights.at_risk_clients.length > 0 ? (
            <div className="space-y-1.5 max-h-60 overflow-auto">
              {insights.at_risk_clients.slice(0, 8).map((c) => (
                <div key={c.client_id} className="flex items-center gap-2 text-xs py-1.5 border-b border-neutral-100 last:border-0">
                  <span className="font-medium text-neutral-700">{c.name}</span>
                  <span className="ml-auto text-red-600 font-mono">{fmtPct(c.churn_risk * 100)} churn</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-neutral-400">No at-risk clients</p>
          )}
        </Card>
      </div>
    </div>
  );
}
