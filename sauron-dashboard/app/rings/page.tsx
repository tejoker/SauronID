"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Line } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum } from "../shared";

/* ── Types matching GET /api/rings ─────────────────────────────────────── */
interface RingSeries {
  label: string;
  dates: string[];
  counts: number[];
}
interface RingLatest {
  ring_id: string;
  label: string;
  count: number;
  first_count: number;
  growth_pct: number;
}
interface RData {
  series: Record<string, RingSeries>;
  latest: RingLatest[];
}

const RING_COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899", "#6366f1", "#14b8a6"];

export default function RingsPage() {
  const [data, setData] = useState<RData | null>(null);

  useEffect(() => {
    sauronFetch<RData>("rings").then(setData).catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  const totalMembers = data.latest.reduce((a, r) => a + r.count, 0);
  const seriesKeys = Object.keys(data.series);
  const allDates = seriesKeys.length > 0 ? data.series[seriesKeys[0]].dates : [];

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">Privacy Rings</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Kpi label="Active Rings" value={String(data.latest.length)} />
        <Kpi label="Total Members" value={fmtNum(totalMembers)} />
        <Kpi label="Avg Ring Size" value={fmtNum(Math.round(totalMembers / (data.latest.length || 1)))} />
        <Kpi label="Largest Ring" value={fmtNum(Math.max(...data.latest.map((r) => r.count), 0))} />
      </div>

      {allDates.length > 0 && (
        <Card title="Ring Growth Over Time">
          <div className="h-60">
            <Line
              data={{
                labels: allDates,
                datasets: seriesKeys.map((key, i) => ({
                  label: data.series[key].label,
                  data: data.series[key].counts,
                  borderColor: RING_COLORS[i % RING_COLORS.length],
                  backgroundColor: RING_COLORS[i % RING_COLORS.length] + "22",
                  fill: false,
                  tension: 0.3,
                  pointRadius: 2,
                  borderWidth: 2,
                })),
              }}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: true, position: "top" as const, labels: { boxWidth: 10, font: { size: 11 } } } },
                scales: {
                  x: { grid: { display: false } },
                  y: { beginAtZero: true, grid: { color: "#f3f4f6" } },
                },
              }}
            />
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {data.latest.map((r, i) => (
          <div key={r.ring_id} className="bg-white border border-neutral-200 rounded-lg p-4 space-y-2">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full" style={{ background: RING_COLORS[i % RING_COLORS.length] }} />
              <span className="text-sm font-semibold text-neutral-800">{r.label}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-xl font-bold tabular-nums text-neutral-900">{fmtNum(r.count)}</span>
              <span className={`text-xs font-medium ${r.growth_pct >= 0 ? "text-emerald-600" : "text-red-600"}`}>
                {r.growth_pct >= 0 ? "+" : ""}
                {r.growth_pct != null ? `${r.growth_pct.toFixed(1)}%` : "—"}
              </span>
            </div>
            <p className="text-[11px] text-neutral-400">{r.ring_id}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
