"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo } from "react";

interface CohortFilterProps {
  vendors: string[];
  sectors: string[];
  periods?: Array<{ value: string; label: string }>;
}

/**
 * Client-side filter strip for the cohort list. Persists vendor/sector/period
 * choice to the URL query string so a refresh keeps the view in sync and the
 * filtered URL can be shared. The cohorts list page reads the same params
 * back from `searchParams` server-side and narrows the dataset.
 */
export function CohortFilter({
  vendors,
  sectors,
  periods,
}: CohortFilterProps) {
  const router = useRouter();
  const sp = useSearchParams();

  const current = useMemo(
    () => ({
      vendor: sp.get("vendor") ?? "all",
      sector: sp.get("sector") ?? "all",
      period: sp.get("period") ?? "latest",
    }),
    [sp]
  );

  const update = useCallback(
    (key: "vendor" | "sector" | "period", value: string) => {
      const next = new URLSearchParams(sp.toString());
      if (value === "all" || value === "latest") {
        next.delete(key);
      } else {
        next.set(key, value);
      }
      const qs = next.toString();
      router.replace(qs ? `?${qs}` : "?");
    },
    [router, sp]
  );

  const selectCls =
    "bg-[var(--bg-surface)] border border-[var(--border)] rounded px-3 py-1.5 " +
    "text-sm text-[var(--text-secondary)] hover:border-[var(--text-muted)] " +
    "focus:outline-none focus:border-[var(--accent)]";

  return (
    <div
      data-testid="cohort-filter"
      className="flex flex-wrap items-center gap-3 mb-6"
    >
      <label className="flex items-center gap-2">
        <span className="text-mono-sm text-[var(--text-muted)] uppercase">
          Vendor
        </span>
        <select
          aria-label="Vendor filter"
          value={current.vendor}
          onChange={(e) => update("vendor", e.target.value)}
          className={selectCls}
        >
          <option value="all">All</option>
          {vendors.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-2">
        <span className="text-mono-sm text-[var(--text-muted)] uppercase">
          Sector
        </span>
        <select
          aria-label="Sector filter"
          value={current.sector}
          onChange={(e) => update("sector", e.target.value)}
          className={selectCls}
        >
          <option value="all">All</option>
          {sectors.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>

      <label className="flex items-center gap-2">
        <span className="text-mono-sm text-[var(--text-muted)] uppercase">
          Period
        </span>
        <select
          aria-label="Period filter"
          value={current.period}
          onChange={(e) => update("period", e.target.value)}
          className={selectCls}
        >
          <option value="latest">Latest</option>
          {(periods ?? []).map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}
