"use client";

import { useDash } from "../context/DashContext";
import { Kpi, Card, fmtNum } from "../shared";

export default function UsersPage() {
  const { users, loading } = useDash();

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="w-8 h-8 border-4 border-neutral-900 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-[1200px]">
      <h1 className="text-lg font-bold text-neutral-900">User Registry</h1>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Kpi label="Total Users" value={fmtNum(users.length)} />
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-neutral-200 text-neutral-400">
                <th className="text-left py-2 font-medium">First Name</th>
                <th className="text-left py-2 font-medium">Last Name</th>
                <th className="text-left py-2 font-medium">Nationality</th>
                <th className="text-left py-2 font-medium">Key Image</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u, i) => (
                <tr key={i} className="border-b border-neutral-100 hover:bg-neutral-50">
                  <td className="py-2 font-medium text-neutral-700">{u.first_name}</td>
                  <td className="py-2 text-neutral-700">{u.last_name}</td>
                  <td className="py-2 text-neutral-500">{u.nationality}</td>
                  <td className="py-2 font-mono text-neutral-400 text-[10px]">
                    {u.key_image_hex?.slice(0, 16)}...
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-neutral-400">
                    No users registered
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-3 text-[10px] text-neutral-400 text-right">
          {users.length} users
        </div>
      </Card>
    </div>
  );
}
