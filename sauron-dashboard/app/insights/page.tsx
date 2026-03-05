"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Line, Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtPct } from "../shared";

/* ── Types matching actual API responses ──────────────────────────────── */
interface ForecastRow {
  month: string;
  revenue_actual: number | null;
  revenue_forecast: number | null;
  ci_lo: number | null;
  ci_hi: number | null;
  is_forecast: boolean;
}
interface LoadRow {
  date: string;
  load_actual: number | null;
  load_forecast: number | null;
  is_forecast: boolean;
}
interface ElasticityMetric {
  metric: string;
  value: number;
  p_value: number | null;
  description: string;
}
interface ClientRow {
  client_id: number;
  name: string;
  type: string;
  sector: string;
  health_score: number;
  trust_score: number;
  churn_risk: number;
  runway_days: number;
  burn_rate: number;
  current_balance: number;
}
interface MLEvent {
  client_id: number;
  name: string;
  date: string;
  anomaly_type: string;
  severity: string;
  anomaly_score: number;
  message: string;
}

interface IData {
  forecast: { actual: ForecastRow[]; forecast: ForecastRow[] };
  load: { historical: LoadRow[]; forecast: LoadRow[] };
  elasticity: { metrics: ElasticityMetric[] };
  clients: { clients: ClientRow[] };
  anomalies_ml: { events: MLEvent[]; total: number };
}

const TYPE_COLORS: Record<string, string> = {
  regulated_issuer: "bg-blue-100 text-blue-700",
  regulated_acquirer: "bg-emerald-100 text-emerald-700",
  fintech: "bg-purple-100 text-purple-700",
  marketplace: "bg-amber-100 text-amber-700",
};

export default function InsightsPage() {
  const [data, setData] = useState<IData | null>(null);

  useEffect(() => {
    Promise.all([
      sauronFetch<IData["forecast"]>("insights/forecast"),
      sauronFetch<IData["load"]>("insights/load"),
      sauronFetch<IData["elasticity"]>("insights/elasticity"),
      sauronFetch<IData["clients"]>("insights/clients"),
      sauronFetch<IData["anomalies_ml"]>("insights/anomalies-ml"),
    ])
      .then(([forecast, load, elasticity, clients, anomalies_ml]) =>
        setData({ forecast, load, elasticity, clients, anomalies_ml })
      )
      .catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  /* ── Revenue Forecast chart data ─────────────────────────────────────── */
  const allForecast = [...data.forecast.actual, ...data.forecast.forecast].sort(
    (a, b) => a.month.localeCompare(b.month)
  );
  const fMonths = allForecast.map((r) => r.month);
  const fActual = allForecast.map((r) => r.revenue_actual);
  const fForecast = allForecast.map((r) => r.revenue_forecast);

  /* ── Load Forecast chart data ────────────────────────────────────────── */
  const allLoad = [...data.load.historical, ...data.load.forecast].sort(
    (a, b) => a.date.localeCompare(b.date)
  );
  const lDates = allLoad.map((r) => r.date);
  const lActual = allLoad.map((r) => r.load_actual);
  const lForecast = allLoad.map((r) => r.load_forecast);

  /* ── Client health summary ───────────────────────────────────────────── */
  const clients = data.clients.clients;
  const avgHealth = clients.length
    ? clients.reduce((a, c) => a + c.health_score, 0) / clients.length
    : 0;
  const highRisk = clients.filter((c) => c.churn_risk > 0.5).length;

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">ML Insights</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Kpi label="Clients Scored" value={String(clients.length)} />
        <Kpi label="Avg Health" value={fmtPct(avgHealth)} accent="text-emerald-600" />
        <Kpi label="ML Anomalies" value={fmtNum(data.anomalies_ml.total)} accent="text-orange-600" />
        <Kpi label="High Churn Risk" value={String(highRisk)} accent="text-red-600" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Revenue Forecast">
          <div className="h-52">
            <Line
              data={{
                labels: fMonths,
                datasets: [
                  { label: "Actual", data: fActual, borderColor: "#3b82f6", backgroundColor: "#3b82f622", fill: true, tension: 0.3, pointRadius: 2, borderWidth: 2, spanGaps: true },
                  { label: "Forecast", data: fForecast, borderColor: "#f59e0b", borderDash: [5, 3], fill: false, tension: 0.3, pointRadius: 2, borderWidth: 2, spanGaps: true },
                ],
              }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: true, position: "top" as const, labels: { boxWidth: 10, font: { size: 11 } } } },
                scales: { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: "#f3f4f6" } } },
              }}
            />
          </div>
        </Card>

        <Card title="Load Forecast">
          <div className="h-52">
            <Line
              data={{
                labels: lDates,
                datasets: [
                  { label: "Actual", data: lActual, borderColor: "#10b981", fill: false, tension: 0.3, pointRadius: 1, borderWidth: 2, spanGaps: true },
                  { label: "Forecast", data: lForecast, borderColor: "#8b5cf6", borderDash: [5, 3], fill: false, tension: 0.3, pointRadius: 1, borderWidth: 2, spanGaps: true },
                ],
              }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: true, position: "top" as const, labels: { boxWidth: 10, font: { size: 11 } } } },
                scales: { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: "#f3f4f6" } } },
              }}
            />
          </div>
        </Card>
      </div>

      {/* Elasticity = correlation metrics from compute_analytics */}
      {data.elasticity.metrics.length > 0 && (
        <Card title="Price Elasticity">
          <div className="h-52">
            <Bar
              data={{
                labels: data.elasticity.metrics.map((e) => e.metric.replace(/_/g, " ")),
                datasets: [{ data: data.elasticity.metrics.map((e) => e.value), backgroundColor: "#10b981", borderRadius: 4 }],
              }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y" as const,
                plugins: { legend: { display: false } },
                scales: { x: { grid: { color: "#f3f4f6" } }, y: { grid: { display: false } } },
              }}
            />
          </div>
        </Card>
      )}

      <Card title="Client Health">
        <div className="overflow-x-auto max-h-72 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white">
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-left py-2 font-medium">Type</th>
                <th className="text-right py-2 font-medium">Health</th>
                <th className="text-right py-2 font-medium">Trust</th>
                <th className="text-right py-2 font-medium">Churn Risk</th>
                <th className="text-right py-2 font-medium">Runway</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => (
                <tr key={c.client_id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{c.name}</td>
                  <td className="py-2">
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${TYPE_COLORS[c.type] || "bg-neutral-100 text-neutral-500"}`}>
                      {c.type}
                    </span>
                  </td>
                  <td className="py-2 text-right tabular-nums">{fmtPct(c.health_score)}</td>
                  <td className="py-2 text-right tabular-nums">{c.trust_score?.toFixed(1) ?? "—"}</td>
                  <td className="py-2 text-right tabular-nums">
                    <span className={c.churn_risk > 0.5 ? "text-red-600 font-medium" : "text-neutral-500"}>{fmtPct(c.churn_risk * 100)}</span>
                  </td>
                  <td className="py-2 text-right tabular-nums">{c.runway_days}d</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="ML Anomaly Detections">
        <div className="overflow-x-auto max-h-64 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white">
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-left py-2 font-medium">Type</th>
                <th className="text-right py-2 font-medium">Score</th>
                <th className="text-left py-2 font-medium">Message</th>
                <th className="text-right py-2 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {data.anomalies_ml.events.slice(0, 50).map((a, i) => (
                <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{a.name}</td>
                  <td className="py-2 text-neutral-500">{a.anomaly_type}</td>
                  <td className="py-2 text-right tabular-nums">
                    <span className={(a.anomaly_score ?? 0) > 0.7 ? "text-red-600 font-medium" : "text-neutral-500"}>{a.anomaly_score?.toFixed(2) ?? "—"}</span>
                  </td>
                  <td className="py-2 text-neutral-500 max-w-xs truncate">{a.message}</td>
                  <td className="py-2 text-right text-neutral-400 tabular-nums">{a.date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
