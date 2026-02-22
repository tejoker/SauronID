"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtPct } from "../shared";

interface VData {
  monthly: { months: string[]; full_kyc: number[]; reduced: number[]; failed: number[]; total: number[] };
  by_type: Record<string, number>;
  total_initial: number | null;
  total_rekyc: number | null;
  per_client: {
    client_id: number;
    name: string;
    type: string;
    full_kyc: number;
    reduced: number;
    total: number;
    fail_rate: number;
  }[];
}

export default function VerificationsPage() {
  const [data, setData] = useState<VData | null>(null);

  useEffect(() => {
    sauronFetch<VData>("verifications").then(setData).catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  const totalFull = data.monthly.full_kyc.reduce((a, b) => a + b, 0);
  const totalReduced = data.monthly.reduced.reduce((a, b) => a + b, 0);
  const totalFailed = data.monthly.failed.reduce((a, b) => a + b, 0);
  const totalAll = data.monthly.total.reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">Verifications</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <Kpi label="Total" value={fmtNum(totalAll)} />
        <Kpi label="Full KYC" value={fmtNum(totalFull)} accent="text-blue-600" />
        <Kpi label="Attribute Queries" value={fmtNum(totalReduced)} accent="text-purple-600" />
        <Kpi label="Failed" value={fmtNum(totalFailed)} accent="text-red-600" />
        {data.total_initial != null && <Kpi label="Initial" value={fmtNum(data.total_initial)} />}
        {data.total_rekyc != null && <Kpi label="Re-KYC" value={fmtNum(data.total_rekyc)} />}
      </div>

      <Card title="Monthly Verification Volume">
        <div className="h-60">
          <Bar
            data={{
              labels: data.monthly.months,
              datasets: [
                { label: "Full KYC", data: data.monthly.full_kyc, backgroundColor: "#3b82f6", borderRadius: 3, stack: "s" },
                { label: "Reduced", data: data.monthly.reduced, backgroundColor: "#a855f7", borderRadius: 3, stack: "s" },
                { label: "Failed", data: data.monthly.failed, backgroundColor: "#ef4444", borderRadius: 3, stack: "s" },
              ],
            }}
            options={{
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { display: true, position: "top" as const, labels: { boxWidth: 10, font: { size: 11 } } } },
              scales: {
                x: { stacked: true, grid: { display: false } },
                y: { stacked: true, beginAtZero: true, grid: { color: "#f3f4f6" } },
              },
            }}
          />
        </div>
      </Card>

      <Card title="Per-Client Breakdown">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-right py-2 font-medium">Full KYC</th>
                <th className="text-right py-2 font-medium">Reduced</th>
                <th className="text-right py-2 font-medium">Total</th>
                <th className="text-right py-2 font-medium">Fail Rate</th>
              </tr>
            </thead>
            <tbody>
              {data.per_client.map((c) => (
                <tr key={c.client_id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{c.name}</td>
                  <td className="py-2 text-right tabular-nums">{fmtNum(c.full_kyc)}</td>
                  <td className="py-2 text-right tabular-nums">{fmtNum(c.reduced)}</td>
                  <td className="py-2 text-right tabular-nums font-medium">{fmtNum(c.total)}</td>
                  <td className="py-2 text-right tabular-nums">
                    <span className={c.fail_rate > 10 ? "text-red-600" : "text-neutral-500"}>
                      {fmtPct(c.fail_rate)}
                    </span>
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
