"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Line, Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtPct, fmtUsd } from "../shared";

interface IData {
  anomalies_ml: {
    anomalies: { client_id: number; client_name: string; score: number; factors: string[] }[];
  };
  clients: {
    segments: { client_id: number; name: string; segment: string; health_score: number; churn_risk: number }[];
  };
  forecast: {
    months: string[];
    actual: number[];
    forecast: number[];
  };
  load: {
    hours: string[];
    actual: number[];
    forecast: number[];
  };
  elasticity: {
    price_points: number[];
    demand: number[];
    optimal_price: number;
  };
}

const SEG_COLORS: Record<string, string> = {
  enterprise: "bg-blue-100 text-blue-700",
  growth: "bg-emerald-100 text-emerald-700",
  startup: "bg-purple-100 text-purple-700",
  at_risk: "bg-red-100 text-red-700",
};

export default function InsightsPage() {
  const [data, setData] = useState<IData | null>(null);

  useEffect(() => {
    Promise.all([
      sauronFetch<IData["anomalies_ml"]>("insights/anomalies-ml"),
      sauronFetch<IData["clients"]>("insights/clients"),
      sauronFetch<IData["forecast"]>("insights/forecast"),
      sauronFetch<IData["load"]>("insights/load"),
      sauronFetch<IData["elasticity"]>("insights/elasticity"),
    ])
      .then(([anomalies_ml, clients, forecast, load, elasticity]) =>
        setData({ anomalies_ml, clients, forecast, load, elasticity })
      )
      .catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  const avgHealth = data.clients.segments.length
    ? data.clients.segments.reduce((a, c) => a + c.health_score, 0) / data.clients.segments.length
    : 0;
  const highRisk = data.anomalies_ml.anomalies.filter((a) => a.score > 0.7).length;

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">ML Insights</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Kpi label="Client Segments" value={String(data.clients.segments.length)} />
        <Kpi label="Avg Health Score" value={fmtPct(avgHealth)} accent="text-emerald-600" />
        <Kpi label="ML Anomalies" value={String(data.anomalies_ml.anomalies.length)} accent="text-orange-600" />
        <Kpi label="High Risk" value={String(highRisk)} accent="text-red-600" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Revenue Forecast">
          <div className="h-52">
            <Line
              data={{
                labels: data.forecast.months,
                datasets: [
                  { label: "Actual", data: data.forecast.actual, borderColor: "#3b82f6", backgroundColor: "#3b82f622", fill: true, tension: 0.3, pointRadius: 2, borderWidth: 2 },
                  { label: "Forecast", data: data.forecast.forecast, borderColor: "#f59e0b", borderDash: [5, 3], fill: false, tension: 0.3, pointRadius: 2, borderWidth: 2 },
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

        <Card title="Load Forecast (24h)">
          <div className="h-52">
            <Line
              data={{
                labels: data.load.hours,
                datasets: [
                  { label: "Actual", data: data.load.actual, borderColor: "#10b981", fill: false, tension: 0.3, pointRadius: 1, borderWidth: 2 },
                  { label: "Forecast", data: data.load.forecast, borderColor: "#8b5cf6", borderDash: [5, 3], fill: false, tension: 0.3, pointRadius: 1, borderWidth: 2 },
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

      <Card title="Price Elasticity">
        <p className="text-xs text-neutral-500 mb-2">Optimal price point: <span className="font-semibold text-neutral-800">{fmtUsd(data.elasticity.optimal_price)}</span></p>
        <div className="h-44">
          <Bar
            data={{
              labels: data.elasticity.price_points.map((p) => fmtUsd(p)),
              datasets: [
                { label: "Demand", data: data.elasticity.demand, backgroundColor: "#6366f1", borderRadius: 3 },
              ],
            }}
            options={{
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { display: false } },
              scales: { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: "#f3f4f6" } } },
            }}
          />
        </div>
      </Card>

      <Card title="Client Health">
        <div className="overflow-x-auto max-h-72 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white">
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-left py-2 font-medium">Segment</th>
                <th className="text-right py-2 font-medium">Health</th>
                <th className="text-right py-2 font-medium">Churn Risk</th>
              </tr>
            </thead>
            <tbody>
              {data.clients.segments.map((c) => (
                <tr key={c.client_id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{c.name}</td>
                  <td className="py-2">
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${SEG_COLORS[c.segment] || "bg-neutral-100 text-neutral-500"}`}>
                      {c.segment}
                    </span>
                  </td>
                  <td className="py-2 text-right tabular-nums">{fmtPct(c.health_score)}</td>
                  <td className="py-2 text-right tabular-nums">
                    <span className={c.churn_risk > 40 ? "text-red-600 font-medium" : "text-neutral-500"}>{fmtPct(c.churn_risk)}</span>
                  </td>
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
                <th className="text-right py-2 font-medium">Score</th>
                <th className="text-left py-2 font-medium">Factors</th>
              </tr>
            </thead>
            <tbody>
              {data.anomalies_ml.anomalies.map((a, i) => (
                <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{a.client_name}</td>
                  <td className="py-2 text-right tabular-nums">
                    <span className={a.score > 0.7 ? "text-red-600 font-medium" : "text-neutral-500"}>{a.score.toFixed(2)}</span>
                  </td>
                  <td className="py-2 text-neutral-500">{a.factors.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
