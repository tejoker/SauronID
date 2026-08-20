"use client";

import { useEffect, useMemo, useRef } from "react";
import {
  Chart,
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
  Title,
  type ChartConfiguration,
} from "chart.js";
import type { CohortMetric } from "@/lib/api";

Chart.register(
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
  Title
);

interface CohortChartProps {
  metric: CohortMetric;
  /**
   * Optional tenant's own value to overlay on the cohort distribution. When
   * provided, the chart annotates which quartile bucket the value lands in
   * via the extra "you" dataset.
   */
  tenantValue?: number | null;
}

/**
 * Quartile fan for a single cohort metric. Renders p25/p50/p75/p95 as four
 * stacked bars + an optional "you" marker bar overlaying the tenant's own
 * value. Uses chart.js (already a dashboard dependency) — no new deps.
 *
 * For suppressed metrics the chart is replaced by an inline notice; we do
 * NOT plot anything because the underlying bucket failed k-anonymity.
 */
export function CohortChart({ metric, tenantValue = null }: CohortChartProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const chartRef = useRef<Chart | null>(null);

  const data = useMemo(() => {
    const labels = ["p25", "p50", "p75", "p95"];
    const values = [
      metric.value_p25,
      metric.value_p50,
      metric.value_p75,
      metric.value_p95,
    ];
    return { labels, values };
  }, [metric]);

  useEffect(() => {
    if (metric.suppressed) return;
    const ctx = canvasRef.current?.getContext("2d");
    if (!ctx) return;

    const datasets: ChartConfiguration<"bar">["data"]["datasets"] = [
      {
        label: "Cohort quartile",
        data: data.values,
        backgroundColor: "#7c87ff",
        borderRadius: 4,
      },
    ];

    if (tenantValue != null) {
      // Plot the tenant value as a flat dataset across all categories so it
      // reads as a reference line without needing the annotation plugin.
      datasets.push({
        label: "You",
        data: data.labels.map(() => tenantValue),
        backgroundColor: "rgba(255, 165, 0, 0.4)",
        borderColor: "orange",
        borderWidth: 1,
        borderRadius: 0,
      });
    }

    const config: ChartConfiguration<"bar"> = {
      type: "bar",
      data: { labels: data.labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { display: tenantValue != null },
          title: { display: true, text: metric.metric_id },
          tooltip: { mode: "index", intersect: false },
        },
        scales: {
          y: { beginAtZero: true },
        },
      },
    };

    chartRef.current?.destroy();
    chartRef.current = new Chart(ctx, config);

    return () => {
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  }, [data, metric, tenantValue]);

  if (metric.suppressed) {
    return (
      <div
        data-testid="cohort-chart-suppressed"
        className="border border-dashed border-[var(--border)] rounded p-6 text-center"
      >
        <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-1">
          {metric.metric_id}
        </p>
        <p className="text-sm text-[var(--text-muted)]">
          Suppressed: cohort size below k-anonymity threshold.
        </p>
      </div>
    );
  }

  return (
    <div
      data-testid="cohort-chart"
      className="h-56 w-full"
      aria-label={`Quartile chart for ${metric.metric_id}`}
    >
      <canvas ref={canvasRef} />
    </div>
  );
}
