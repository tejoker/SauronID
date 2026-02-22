"use client";

/* ── API helpers ─────────────────────────────────────────────────────────── */

const DASH_API =
  typeof window !== "undefined"
    ? (process.env.NEXT_PUBLIC_DASH_API_URL ?? "http://localhost:8002")
    : "http://localhost:8002";

export async function sauronFetch<T>(path: string): Promise<T> {
  const url = `${DASH_API}/api/${path.replace(/^\//, "")}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Sauron API ${path}: ${res.status}`);
  return res.json();
}

/* ── KPI Card ────────────────────────────────────────────────────────────── */
export function Kpi({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="bg-white rounded-2xl p-4 flex flex-col gap-1" style={{boxShadow:"0 1px 3px rgba(0,0,0,0.07),0 1px 2px rgba(0,0,0,0.04)"}}>
      <span className="text-[11px] font-medium text-[#8e8e93] uppercase tracking-wide">
        {label}
      </span>
      <span
        className={`text-[28px] font-bold tabular-nums leading-none ${accent ?? "text-[#1c1c1e]"}`}
      >
        {value}
      </span>
      {sub && (
        <span className="text-xs text-[#8e8e93]">{sub}</span>
      )}
    </div>
  );
}

/* ── Section Header ──────────────────────────────────────────────────────── */
export function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-3">
      <h2 className="text-sm font-semibold text-neutral-700 uppercase tracking-wider">
        {title}
      </h2>
      {children}
    </section>
  );
}

/* ── Card ─────────────────────────────────────────────────────────────────── */
export function Card({
  title,
  children,
  className,
}: {
  title?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-white rounded-2xl p-5 ${className ?? ""}`}
      style={{boxShadow:"0 1px 3px rgba(0,0,0,0.07),0 1px 2px rgba(0,0,0,0.04)"}}
    >
      {title && (
        <h3 className="text-[11px] font-semibold text-[#8e8e93] uppercase tracking-wider mb-4">
          {title}
        </h3>
      )}
      {children}
    </div>
  );
}

/* ── Spinner ──────────────────────────────────────────────────────────────── */
export function Spinner() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="w-8 h-8 border-[3px] border-[#007AFF] border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

/* ── Format helpers ───────────────────────────────────────────────────────── */
export function fmtNum(n: number | null | undefined, decimals = 0): string {
  if (n == null) return "\u2014";
  return n.toLocaleString("en-US", { maximumFractionDigits: decimals });
}

export function fmtPct(n: number | null | undefined): string {
  if (n == null) return "\u2014";
  return `${n.toFixed(1)}%`;
}

export function fmtUsd(n: number | null | undefined): string {
  if (n == null) return "\u2014";
  return `$${fmtNum(n, 2)}`;
}
