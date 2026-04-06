"use client";

import { useEffect, useState, useCallback } from "react";
import { Card } from "../shared";

interface RequestEvent {
  client_name: string;
  request_type: string;
  timestamp: string;
  success: boolean;
}

export default function RequestsPage() {
  const [events, setEvents] = useState<RequestEvent[]>([]);

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/admin/requests`);
      if (res.ok) setEvents(await res.json());
    } catch {}
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5_000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <div className="space-y-6 max-w-[1200px]">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-neutral-900">Activity Log</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-neutral-400">{events.length} events</span>
          <button
            onClick={load}
            className="px-3 py-1.5 text-xs border border-neutral-200 rounded-md hover:bg-neutral-50 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">#</th>
                <th className="text-left py-2 font-medium">Client</th>
                <th className="text-left py-2 font-medium">Type</th>
                <th className="text-left py-2 font-medium">Timestamp</th>
                <th className="text-center py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-neutral-400">
                    No activity yet
                  </td>
                </tr>
              ) : (
                events.map((e, i) => (
                  <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                    <td className="py-2 tabular-nums text-neutral-400">{i + 1}</td>
                    <td className="py-2 font-medium text-neutral-700">{e.client_name}</td>
                    <td className="py-2">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded ${
                          e.request_type === "register"
                            ? "bg-blue-50 text-blue-700"
                            : e.request_type === "login"
                              ? "bg-green-50 text-green-700"
                              : "bg-neutral-100 text-neutral-600"
                        }`}
                      >
                        {e.request_type}
                      </span>
                    </td>
                    <td className="py-2 text-neutral-400 tabular-nums">{e.timestamp}</td>
                    <td className="py-2 text-center">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                          e.success
                            ? "bg-green-50 text-green-700"
                            : "bg-red-50 text-red-600"
                        }`}
                      >
                        {e.success ? "OK" : "FAIL"}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
