"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Doughnut, Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtPct } from "../shared";

interface MonthlyHistory { month: string; purged: number }
interface RunLogEntry {
  run_date: string;
  newly_purged: number;
  total_anonymized: number;
  eligible_remaining: number;
  eu_eea_scope: number;
}

interface GData {
  total_users: number;
  eu_eea_scope: number;
  non_eu_total: number;
  active_users: number;
  anonymized_total: number;
  pending_purge: number;
  retention_days: number;
  cutoff_date: string;
  last_run_date: string | null;
  last_run_purged: number;
  monthly_history: MonthlyHistory[];
  run_log: RunLogEntry[];
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

  const purgeRate = data.total_users > 0 ? (data.anonymized_total / data.total_users) * 100 : 0;

  const scopeLabels = ["EU/EEA Active", "Anonymized", "Non-EU/EEA"];
  const scopeValues = [data.active_users, data.anonymized_total, data.non_eu_total];
  const scopeColors = ["#3b82f6", "#ef4444", "#10b981"];

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

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <Kpi label="Total Users" value={fmtNum(data.total_users)} />
        <Kpi label="EU/EEA Scope" value={fmtNum(data.eu_eea_scope)} accent="text-blue-600" />
        <Kpi label="Anonymized" value={fmtNum(data.anonymized_total)} accent="text-red-600" />
        <Kpi label="Pending Purge" value={fmtNum(data.pending_purge)} accent={data.pending_purge > 0 ? "text-amber-600" : "text-green-600"} />
        <Kpi label="Purge Rate" value={fmtPct(purgeRate)} />
        <Kpi label="Retention" value={`${data.retention_days}d`} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="User Scope Breakdown">
          <div className="h-52 flex items-center justify-center">
            <Doughnut
              data={{
                labels: scopeLabels,
                datasets: [
                  {
                    data: scopeValues,
                    backgroundColor: scopeColors,
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
                labels: data.monthly_history.map((h) => h.month),
                datasets: [
                  { label: "Purged", data: data.monthly_history.map((h) => h.purged), backgroundColor: "#ef4444", borderRadius: 3 },
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <Card title="Last Purge Run">
          <div className="text-xs space-y-2">
            <div className="flex justify-between"><span className="text-neutral-400">Date</span><span className="font-mono text-neutral-700">{data.last_run_date ?? "Never"}</span></div>
            <div className="flex justify-between"><span className="text-neutral-400">Records Purged</span><span className="font-mono text-neutral-700">{fmtNum(data.last_run_purged)}</span></div>
            <div className="flex justify-between"><span className="text-neutral-400">Cutoff Date</span><span className="font-mono text-neutral-700">{data.cutoff_date}</span></div>
          </div>
        </Card>
        <Card title="Active vs Anonymized">
          <div className="text-xs space-y-2">
            <div className="flex justify-between"><span className="text-neutral-400">Active EU/EEA</span><span className="font-mono text-blue-600">{fmtNum(data.active_users)}</span></div>
            <div className="flex justify-between"><span className="text-neutral-400">Anonymized</span><span className="font-mono text-red-600">{fmtNum(data.anonymized_total)}</span></div>
            <div className="flex justify-between"><span className="text-neutral-400">Non-EU/EEA</span><span className="font-mono text-emerald-600">{fmtNum(data.non_eu_total)}</span></div>
          </div>
        </Card>
        <Card title="Compliance Status">
          <div className="text-xs space-y-2">
            <div className="flex justify-between"><span className="text-neutral-400">Retention Policy</span><span className="font-medium text-neutral-700">{data.retention_days} days</span></div>
            <div className="flex justify-between"><span className="text-neutral-400">Pending Purge</span>
              <span className={`font-medium ${data.pending_purge === 0 ? "text-green-600" : "text-amber-600"}`}>
                {data.pending_purge === 0 ? "Compliant" : `${fmtNum(data.pending_purge)} records`}
              </span>
            </div>
          </div>
        </Card>
      </div>

      <Card title="Purge Audit Log">
        <div className="overflow-x-auto max-h-56 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-white">
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Run Date</th>
                <th className="text-right py-2 font-medium">Newly Purged</th>
                <th className="text-right py-2 font-medium">Total Anonymized</th>
                <th className="text-right py-2 font-medium">Eligible Remaining</th>
                <th className="text-right py-2 font-medium">EU/EEA Scope</th>
              </tr>
            </thead>
            <tbody>
              {data.run_log.map((r, i) => (
                <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 text-neutral-700 font-mono">{r.run_date}</td>
                  <td className="py-2 text-right tabular-nums text-red-600">{fmtNum(r.newly_purged)}</td>
                  <td className="py-2 text-right tabular-nums">{fmtNum(r.total_anonymized)}</td>
                  <td className="py-2 text-right tabular-nums">{fmtNum(r.eligible_remaining)}</td>
                  <td className="py-2 text-right tabular-nums">{fmtNum(r.eu_eea_scope)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
