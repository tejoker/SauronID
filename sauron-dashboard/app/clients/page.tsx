"use client";

import { useEffect, useState } from "react";
import { sauronFetch, Kpi, Card, Spinner, fmtNum } from "../shared";

interface ClientRow {
  client_id: number;
  name: string;
  type: string;
  balance_a?: number;
  balance_b?: number;
  last_active?: string;
  total_verifications?: number;
  is_active?: boolean;
}

interface ClientsData {
  clients: ClientRow[];
  active_count: number;
}

export default function ClientsPage() {
  const [data, setData] = useState<ClientsData | null>(null);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");

  useEffect(() => {
    sauronFetch<ClientsData>("clients").then(setData).catch(() => {});
  }, []);

  if (!data) return <Spinner />;

  const filtered = data.clients.filter((c) => {
    if (typeFilter !== "all" && c.type !== typeFilter) return false;
    return c.name.toLowerCase().includes(search.toLowerCase());
  });

  const types = [...new Set(data.clients.map((c) => c.type))];

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">Client Directory</h1>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Kpi label="Total Clients" value={fmtNum(data.clients.length)} />
        <Kpi label="Active (90d)" value={fmtNum(data.active_count)} accent="text-green-600" />
        <Kpi label="Inactive" value={fmtNum(data.clients.length - data.active_count)} accent={data.clients.length - data.active_count > 0 ? "text-amber-600" : "text-neutral-400"} />
      </div>

      <Card>
        <div className="flex items-center gap-3 mb-4">
          <input
            type="text"
            placeholder="Search clients..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="px-3 py-1.5 text-xs border border-neutral-200 rounded-md focus:outline-none focus:border-neutral-400 w-56"
          />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-1.5 text-xs border border-neutral-200 rounded-md focus:outline-none"
          >
            <option value="all">All Types</option>
            {types.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <span className="text-xs text-neutral-400 ml-auto">
            {filtered.length} clients
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">Name</th>
                <th className="text-left py-2 font-medium">Type</th>
                <th className="text-right py-2 font-medium">Balance A</th>
                <th className="text-right py-2 font-medium">Balance B</th>
                <th className="text-right py-2 font-medium">Verifications</th>
                <th className="text-center py-2 font-medium">Status</th>
                <th className="text-right py-2 font-medium">Last Active</th>
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
                  <td className="py-2 text-right tabular-nums text-blue-600">
                    {fmtNum(c.balance_a ?? 0)}
                  </td>
                  <td className="py-2 text-right tabular-nums text-orange-500">
                    {fmtNum(c.balance_b ?? 0)}
                  </td>
                  <td className="py-2 text-right tabular-nums">
                    {fmtNum(c.total_verifications ?? 0)}
                  </td>
                  <td className="py-2 text-center">
                    <span
                      className={`w-2 h-2 rounded-full inline-block ${
                        c.is_active ? "bg-green-500" : "bg-neutral-300"
                      }`}
                    />
                  </td>
                  <td className="py-2 text-right text-neutral-400">
                    {c.last_active?.slice(0, 10) ?? "---"}
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
