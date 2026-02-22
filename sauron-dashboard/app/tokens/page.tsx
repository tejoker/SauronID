"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtUsd } from "../shared";

interface TokenClient {
  client_id: number;
  name: string;
  type: string;
  bal_a: number;
  bal_b: number;
  flow_30d: number;
  runway_days: number;
}

interface TokensData {
  clients: TokenClient[];
  low_balance_alerts: TokenClient[];
  credit_summary: Record<string, number>;
  monthly_credit_a: { months: string[]; credit_a: number[] };
}

export default function TokensPage() {
  const [data, setData] = useState<TokensData | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    sauronFetch<TokensData>("tokens").then(setData).catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  const cs = data.credit_summary;
  const filtered = data.clients.filter((c) =>
    c.name.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">Token Ledger</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Kpi label="Credit A Minted" value={fmtNum(cs.credit_a_total_minted)} accent="text-blue-600" />
        <Kpi label="Credit B Converted" value={fmtNum(cs.credit_b_converted)} accent="text-orange-500" />
        <Kpi label="Exchange Rate" value={`1:${cs.exchange_rate}`} />
        <Kpi
          label="Low Balance Alerts"
          value={data.low_balance_alerts.length}
          accent={data.low_balance_alerts.length > 0 ? "text-red-600" : "text-green-600"}
        />
      </div>

      <Card title="Monthly Credit A Issuance">
        <div className="h-52">
          <Bar
            data={{
              labels: data.monthly_credit_a.months,
              datasets: [
                {
                  data: data.monthly_credit_a.credit_a,
                  backgroundColor: "#3b82f6",
                  borderRadius: 4,
                },
              ],
            }}
            options={{
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { display: false } },
              scales: {
                x: { grid: { display: false } },
                y: { beginAtZero: true, grid: { color: "#f3f4f6" } },
              },
            }}
          />
        </div>
      </Card>

      <Card>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-semibold text-neutral-500 uppercase tracking-wider">
            Client Balances
          </h3>
          <input
            type="text"
            placeholder="Search..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="px-3 py-1.5 text-xs border border-neutral-200 rounded-md focus:outline-none focus:border-neutral-400 w-48"
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-left py-2 font-medium">Type</th>
                <th className="text-right py-2 font-medium">Balance A</th>
                <th className="text-right py-2 font-medium">Balance B</th>
                <th className="text-right py-2 font-medium">30d Flow</th>
                <th className="text-right py-2 font-medium">Runway</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr key={c.client_id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{c.name}</td>
                  <td className="py-2">
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded ${
                        c.type === "full_identification"
                          ? "bg-blue-50 text-blue-700"
                          : "bg-purple-50 text-purple-700"
                      }`}
                    >
                      {c.type}
                    </span>
                  </td>
                  <td className="py-2 text-right tabular-nums text-blue-600">{fmtNum(c.bal_a)}</td>
                  <td className="py-2 text-right tabular-nums text-orange-500">{fmtNum(c.bal_b)}</td>
                  <td className="py-2 text-right tabular-nums">{fmtNum(c.flow_30d)}</td>
                  <td className="py-2 text-right tabular-nums">
                    {c.runway_days > 0 ? `${fmtNum(c.runway_days)}d` : "---"}
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
