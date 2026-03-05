"use client";

import { useEffect, useState } from "react";
import "../chartSetup";
import { Bar } from "react-chartjs-2";
import { sauronFetch, Kpi, Card, Spinner, fmtNum, fmtUsd } from "../shared";

interface TokensData {
  clients: { client_id: number; name: string; type: string; bal_a: number; bal_b: number }[];
  monthly_conversions: { months: string[]; credit_b_converted: number[] };
  monthly_credit_a: { months: string[]; credit_a: number[] };
  monthly_credit_b: { months: string[]; credit_b: number[]; revenue: number[] };
  credit_summary: Record<string, number>;
}

export default function CreditsPage() {
  const [data, setData] = useState<TokensData | null>(null);

  useEffect(() => {
    sauronFetch<TokensData>("tokens").then(setData).catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  const cs = data.credit_summary;

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">Credit Economy</h1>

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-3">
        <Kpi label="KYC Revenue" value={`$${fmtNum(Math.round(cs.kyc_revenue_gross ?? cs.kyc_revenue_usd))}`} accent="text-green-600" />
        <Kpi label="Query Revenue" value={`$${fmtNum(Math.round(cs.query_revenue_usd))}`} accent="text-green-600" />
        <Kpi label="Credit A Minted" value={fmtNum(cs.credit_a_total_minted)} accent="text-blue-600" />
        <Kpi label="A Converted" value={fmtNum(cs.credit_a_converted)} />
        <Kpi label="B Converted" value={fmtNum(cs.credit_b_converted)} accent="text-orange-500" />
        <Kpi label="Exchange Rate" value={cs.exchange_rate ? `1A = ${cs.exchange_rate}B` : "\u2014"} sub={cs.credit_b_usd ? `B @ ${fmtUsd(cs.credit_b_usd)}` : undefined} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Monthly Credit A Issuance">
          <div className="h-52">
            <Bar
              data={{
                labels: data.monthly_credit_a.months,
                datasets: [{ data: data.monthly_credit_a.credit_a, backgroundColor: "#3b82f6", borderRadius: 4 }],
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

        <Card title="Monthly B Conversions">
          <div className="h-52">
            {(() => {
              const months = data.monthly_conversions?.months ?? [];
              const converted = data.monthly_conversions?.credit_b_converted ?? [];
              const pairs = months
                .map((m, i) => ({ m, v: Math.round(converted[i] ?? 0) }))
                .filter((p) => p.v > 0);
              if (pairs.length === 0) return <p className="text-xs text-[#8e8e93] pt-2">No conversion data</p>;
              return (
                <Bar
                  data={{
                    labels: pairs.map((p) => p.m),
                    datasets: [{ data: pairs.map((p) => p.v), backgroundColor: "#f97316", borderRadius: 4 }],
                  }}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: { x: { grid: { display: false } }, y: { beginAtZero: true, grid: { color: "#f3f4f6" } } },
                  }}
                />
              );
            })()}
          </div>
        </Card>
      </div>

      <Card title="Client Credit Breakdown">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-left py-2 font-medium">Type</th>
                <th className="text-right py-2 font-medium">Credit A</th>
                <th className="text-right py-2 font-medium">Credit B</th>
              </tr>
            </thead>
            <tbody>
              {data.clients.slice(0, 30).map((c) => (
                <tr key={c.client_id} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{c.name}</td>
                  <td className="py-2 text-neutral-500">{c.type}</td>
                  <td className="py-2 text-right tabular-nums text-blue-600">{fmtNum(c.bal_a)}</td>
                  <td className="py-2 text-right tabular-nums text-orange-500">{fmtNum(c.bal_b)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
