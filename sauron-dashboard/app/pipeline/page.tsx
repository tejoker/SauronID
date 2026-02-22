"use client";

import { useEffect, useState, useRef } from "react";
import "../chartSetup";
import { Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtPct } from "../shared";

const DASH_API = process.env.NEXT_PUBLIC_ANALYTICS_URL || "http://localhost:8002";

interface PData {
  live?: boolean;
  throughput: number;
  avg_latency_ms: number;
  uptime_pct: number;
  fraud_detected: number;
  total_events?: number;
  latency: { service: string; ms: number }[];
  resources: { name: string; cpu_pct: number; mem_mb: number; status: string }[];
}

interface FraudEvent {
  id: string;
  type: string;
  score: number;
  client: string;
  ts: string;
}

export default function PipelinePage() {
  const [data, setData] = useState<PData | null>(null);
  const [error, setError] = useState(false);
  const [fraudEvents, setFraudEvents] = useState<FraudEvent[]>([]);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    sauronFetch<PData>("pipeline-stats").then(setData).catch(() => setError(true));
  }, []);

  useEffect(() => {
    try {
      const es = new EventSource(`${DASH_API}/api/fraud-stream`);
      esRef.current = es;
      es.onmessage = (e) => {
        try {
          const ev = JSON.parse(e.data) as FraudEvent;
          if (ev.score == null || ev.type == null) return; // skip error/malformed events
          setFraudEvents((prev) => [ev, ...prev].slice(0, 50));
        } catch { /* ignore */ }
      };
      es.onerror = () => {};
    } catch { /* ignore */ }
    return () => esRef.current?.close();
  }, []);

  if (error) return (
    <div className="space-y-4 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">Pipeline</h1>
      <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">
        Failed to load pipeline data. The analytics API may be unavailable.
        <button onClick={() => { setError(false); sauronFetch<PData>("pipeline-stats").then(setData).catch(() => setError(true)); }}
          className="ml-3 text-xs px-3 py-1 rounded bg-red-600 text-white hover:bg-red-700">Retry</button>
      </div>
    </div>
  );

  if (!data) return <Spinner />;

  const STATUS_COLORS: Record<string, string> = {
    healthy: "bg-emerald-100 text-emerald-700",
    degraded: "bg-yellow-100 text-yellow-700",
    down: "bg-red-100 text-red-700",
  };

  return (
    <div className="space-y-6 max-w-[1200px]">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-neutral-900">Pipeline</h1>
        {data.live === false && (
          <span className="text-xs px-2.5 py-1 rounded-full bg-amber-50 text-amber-600 font-medium">
            Static snapshot (ingest offline)
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Kpi label="Throughput" value={`${fmtNum(data.throughput)}/s`} />
        <Kpi label="Avg Latency" value={`${data.avg_latency_ms}ms`} />
        <Kpi label="Uptime" value={fmtPct(data.uptime_pct)} accent="text-emerald-600" />
        <Kpi label="Fraud Detected" value={fmtNum(data.fraud_detected)} accent="text-red-600" />
        {data.total_events != null && <Kpi label="Total Events" value={fmtNum(data.total_events)} />}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Service Latency">
          <div className="h-52">
            <Bar
              data={{
                labels: data.latency.map((l) => l.service),
                datasets: [
                  {
                    label: "ms",
                    data: data.latency.map((l) => l.ms),
                    backgroundColor: data.latency.map((l) =>
                      l.ms > 200 ? "#ef4444" : l.ms > 100 ? "#f59e0b" : "#10b981"
                    ),
                    borderRadius: 3,
                  },
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

        <Card title="System Resources">
          <div className="space-y-2">
            {data.resources.map((r) => (
              <div key={r.name} className="flex items-center gap-3 text-xs">
                <span className="w-28 font-medium text-neutral-700 truncate">{r.name}</span>
                <div className="flex-1">
                  <div className="h-2 bg-neutral-100 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${Math.min(r.cpu_pct, 100)}%`,
                        background: r.cpu_pct > 80 ? "#ef4444" : r.cpu_pct > 50 ? "#f59e0b" : "#10b981",
                      }}
                    />
                  </div>
                </div>
                <span className="text-neutral-500 tabular-nums w-10 text-right">{r.cpu_pct}%</span>
                <span className="text-neutral-400 tabular-nums w-16 text-right">{r.mem_mb}MB</span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${STATUS_COLORS[r.status] || "bg-neutral-100 text-neutral-500"}`}>
                  {r.status}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Live Fraud Stream">
        {fraudEvents.length === 0 ? (
          <p className="text-xs text-neutral-400">Waiting for events...</p>
        ) : (
          <div className="overflow-x-auto max-h-56 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-white">
                <tr className="border-b border-neutral-200 text-neutral-400">
                  <th className="text-left py-2 font-medium">Type</th>
                  <th className="text-left py-2 font-medium">Client</th>
                  <th className="text-right py-2 font-medium">Score</th>
                  <th className="text-right py-2 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {fraudEvents.map((e, i) => (
                  <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                    <td className="py-2 text-neutral-600">{e.type}</td>
                    <td className="py-2 font-medium text-neutral-700">{e.client}</td>
                    <td className="py-2 text-right tabular-nums">
                      <span className={e.score > 0.7 ? "text-red-600 font-medium" : "text-neutral-500"}>{e.score.toFixed(2)}</span>
                    </td>
                    <td className="py-2 text-right text-neutral-400 tabular-nums">{e.ts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
