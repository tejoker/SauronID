"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum } from "../shared";

/* ── Types matching GET /api/anomalies ─────────────────────────────────── */
interface AEvent {
  client_id: number;
  date: string;
  anomaly_type: string;
  severity: string;
  message: string;
  name: string;       // client name (from join)
  type: string;       // client type
}
interface ByTypeRow { anomaly_type: string; count: number }
interface BySevRow  { severity: string; count: number }
interface AData {
  events: AEvent[];
  by_type: ByTypeRow[];
  by_severity: BySevRow[];
  monthly: { months: string[]; counts: number[] };
}

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-100 text-red-700",
  high: "bg-orange-100 text-orange-700",
  medium: "bg-yellow-100 text-yellow-700",
  low: "bg-blue-100 text-blue-700",
};

interface MlAnomalies {
  events: unknown[];
  total: number;
  precision_proxy: number | null;
}

export default function AnomaliesPage() {
  const [data, setData] = useState<AData | null>(null);
  const [ml, setMl] = useState<MlAnomalies | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [resiliated, setResiiated] = useState<Set<number>>(new Set());

  function resiliate(clientId: number) {
    setResiiated((prev) => new Set(prev).add(clientId));
  }

  useEffect(() => {
    Promise.all([
      sauronFetch<AData>("anomalies"),
      sauronFetch<MlAnomalies>("insights/anomalies-ml").catch(() => null),
    ]).then(([a, m]) => { setData(a); setMl(m); });
  }, []);

  if (!data) return <Spinner />;

  const sevMap: Record<string, number> = {};
  (data.by_severity ?? []).forEach((s) => { sevMap[s.severity] = s.count; });

  const filtered = filter === "all" ? data.events : data.events.filter((e) => e.severity === filter);

  const typeLabels = data.by_type.map((t) => t.anomaly_type);
  const typeValues = data.by_type.map((t) => t.count);

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">Anomalies</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Kpi label="Total Anomalies" value={fmtNum(data.events.length)} />
        <Kpi label="High Severity" value={fmtNum(sevMap["high"] || 0)} accent="text-red-600" />
        {ml && <Kpi label="ML Detected" value={fmtNum(ml.total)} accent="text-purple-600" />}
        {ml?.precision_proxy != null && <Kpi label="ML Precision" value={`${(ml.precision_proxy * 100).toFixed(1)}%`} />}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Monthly Anomaly Count">
          <div className="h-48">
            <Bar
              data={{
                labels: data.monthly.months,
                datasets: [
                  { label: "Anomalies", data: data.monthly.counts, backgroundColor: "#ef4444", borderRadius: 3 },
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

        <Card title="By Type">
          <div className="h-48">
            <Bar
              data={{
                labels: typeLabels,
                datasets: [
                  { label: "Count", data: typeValues, backgroundColor: "#8b5cf6", borderRadius: 3 },
                ],
              }}
              options={{
                indexAxis: "y" as const,
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { x: { beginAtZero: true, grid: { color: "#f3f4f6" } }, y: { grid: { display: false } } },
              }}
            />
          </div>
        </Card>
      </div>

      <Card title="Event Feed">
        <div className="flex gap-2 mb-3 flex-wrap">
          {["all", "critical", "high", "medium", "low"].map((s) => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`text-xs px-3 py-1 rounded-full border transition ${
                filter === s
                  ? "bg-neutral-900 text-white border-neutral-900"
                  : "bg-white text-neutral-500 border-neutral-200 hover:border-neutral-400"
              }`}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <div className="overflow-x-auto max-h-80 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white">
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Severity</th>
                <th className="text-left py-2 font-medium">Type</th>
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-left py-2 font-medium">Description</th>
                <th className="text-right py-2 font-medium">Date</th>
                <th className="py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 60).map((e, i) => (
                <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2">
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${SEV_COLORS[e.severity] || "bg-neutral-100 text-neutral-500"}`}>
                      {e.severity}
                    </span>
                  </td>
                  <td className="py-2 text-neutral-600">{e.anomaly_type}</td>
                  <td className="py-2 font-medium text-neutral-700">{e.name}</td>
                  <td className="py-2 text-neutral-500 max-w-xs truncate">{e.message}</td>
                  <td className="py-2 text-right text-neutral-400 tabular-nums">{e.date}</td>
                  <td className="py-2 pl-3">
                    {resiliated.has(e.client_id) ? (
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-neutral-100 text-neutral-400 font-medium">Resiliated</span>
                    ) : (
                      <button
                        onClick={() => resiliate(e.client_id)}
                        className="text-[10px] px-2 py-0.5 rounded-full border border-red-300 text-red-600 hover:bg-red-50 transition font-medium whitespace-nowrap"
                      >
                        Resiliate user
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
