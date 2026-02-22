"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Doughnut, Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtPct } from "../shared";

interface GData {
  retention: Record<string, number>;
  total_users: number;
  purged_users: number;
  purge_rate: number;
  monthly_purges: { months: string[]; counts: number[] };
  policies: { name: string; retention_days: number; auto_purge: boolean }[];
  recent_purges: { user_id: string; purged_at: string; data_types: string[] }[];
}

export default function GdprPage() {
  const [data, setData] = useState<GData | null>(null);
  const [purging, setPurging] = useState(false);
  const [purgeResult, setPurgeResult] = useState<string | null>(null);

  useEffect(() => {
    sauronFetch<GData>("gdpr/stats").then(setData).catch(() => {});
  }, []);

  const executePurge = async () => {
    setPurging(true);
    setPurgeResult(null);
    try {
      const r = await sauronFetch<{ purged: number; message: string }>("gdpr/purge");
      setPurgeResult(`Purged ${r.purged} records. ${r.message}`);
      sauronFetch<GData>("gdpr/stats").then(setData);
    } catch {
      setPurgeResult("Purge failed.");
    } finally {
      setPurging(false);
    }
  };

  if (!data) return <Spinner />;

  const retentionLabels = Object.keys(data.retention);
  const retentionValues = Object.values(data.retention);
  const retentionColors = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

  return (
    <div className="space-y-6 max-w-[1200px]">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-neutral-900">GDPR Compliance</h1>
        <button
          onClick={executePurge}
          disabled={purging}
          className="text-xs px-4 py-2 rounded-lg bg-red-600 text-white hover:bg-red-700 disabled:opacity-50 transition font-medium"
        >
          {purging ? "Purging..." : "Execute Purge"}
        </button>
      </div>

      {purgeResult && (
        <div className="text-xs px-3 py-2 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200">
          {purgeResult}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Kpi label="Total Users" value={fmtNum(data.total_users)} />
        <Kpi label="Purged Users" value={fmtNum(data.purged_users)} accent="text-red-600" />
        <Kpi label="Purge Rate" value={fmtPct(data.purge_rate)} />
        <Kpi label="Retention Cats" value={String(retentionLabels.length)} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Data Retention Breakdown">
          <div className="h-52 flex items-center justify-center">
            <Doughnut
              data={{
                labels: retentionLabels,
                datasets: [
                  {
                    data: retentionValues,
                    backgroundColor: retentionColors.slice(0, retentionLabels.length),
                    borderWidth: 0,
                  },
                ],
              }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: true, position: "right" as const, labels: { boxWidth: 10, font: { size: 11 } } } },
              }}
            />
          </div>
        </Card>

        <Card title="Monthly Purge History">
          <div className="h-52">
            <Bar
              data={{
                labels: data.monthly_purges.months,
                datasets: [
                  { label: "Purges", data: data.monthly_purges.counts, backgroundColor: "#ef4444", borderRadius: 3 },
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
      </div>

      <Card title="Retention Policies">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Policy Name</th>
                <th className="text-right py-2 font-medium">Retention (days)</th>
                <th className="text-right py-2 font-medium">Auto-Purge</th>
              </tr>
            </thead>
            <tbody>
              {data.policies.map((p, i) => (
                <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{p.name}</td>
                  <td className="py-2 text-right tabular-nums">{p.retention_days}</td>
                  <td className="py-2 text-right">
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${p.auto_purge ? "bg-emerald-100 text-emerald-700" : "bg-neutral-100 text-neutral-500"}`}>
                      {p.auto_purge ? "ON" : "OFF"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Recent Purge Audit Log">
        <div className="overflow-x-auto max-h-56 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white">
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">User ID</th>
                <th className="text-left py-2 font-medium">Purged At</th>
                <th className="text-left py-2 font-medium">Data Types</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_purges.map((p, i) => (
                <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 text-neutral-700 font-mono">{p.user_id}</td>
                  <td className="py-2 text-neutral-500 tabular-nums">{p.purged_at}</td>
                  <td className="py-2 text-neutral-500">{p.data_types.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
