"use client";

// Policy simulator panel: paste an action JSON + optional spend override,
// hit Evaluate, render the verdict + per-check trace. All authority is
// server-side (`POST /api/policies/[id]/evaluate`). Without an agent_id
// the server flags the response with `simulator: true` and the warning
// surfaced inline.

import { useState } from "react";
import { evaluatePolicy, type EvaluateResult, type PolicyVerdict } from "@/lib/api";

interface PolicySimulatorProps {
  policyId: string;
}

const DEFAULT_ACTION = `{
  "action_id": "act_sim_1",
  "tool": "http_get",
  "amount_usd": 0,
  "signatures": [],
  "delegation_depth": 0,
  "timestamp": ${Math.floor(Date.now() / 1000)}
}`;

export function PolicySimulator({ policyId }: PolicySimulatorProps) {
  const [actionText, setActionText] = useState(DEFAULT_ACTION);
  const [spendOverride, setSpendOverride] = useState("");
  const [agentId, setAgentId] = useState("");
  const [result, setResult] = useState<EvaluateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function run() {
    setError(null);
    setResult(null);
    setPending(true);
    try {
      let action: Record<string, unknown>;
      try {
        action = JSON.parse(actionText) as Record<string, unknown>;
      } catch (e) {
        setError(`Action is not valid JSON: ${e instanceof Error ? e.message : "unknown"}`);
        return;
      }
      const ctxOverrides: Record<string, unknown> = {};
      if (spendOverride.trim() !== "") {
        const n = Number(spendOverride);
        if (!Number.isFinite(n)) {
          setError("Spend override must be a number.");
          return;
        }
        ctxOverrides.spend_total_usd = n;
      }
      const body: {
        action: Record<string, unknown>;
        context_overrides?: Record<string, unknown>;
        agent_id?: string;
      } = { action };
      if (Object.keys(ctxOverrides).length > 0) {
        body.context_overrides = ctxOverrides;
      }
      if (agentId.trim() !== "") {
        body.agent_id = agentId.trim();
      }
      const r = await evaluatePolicy(policyId, body);
      if (!r.ok) {
        setError(r.error);
      } else {
        setResult(r.data);
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <label htmlFor="policy-sim-action" className="block text-mono-sm text-[var(--text-muted)] uppercase mb-2">
          Action JSON
        </label>
        <textarea
          id="policy-sim-action"
          value={actionText}
          onChange={(e) => setActionText(e.target.value)}
          rows={10}
          spellCheck={false}
          className="w-full font-mono text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded-lg px-4 py-3 text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] resize-y"
        />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label
            htmlFor="sim-spend-override"
            className="block text-mono-sm text-[var(--text-muted)] uppercase mb-2"
          >
            Spend override (USD)
          </label>
          <input
            id="sim-spend-override"
            value={spendOverride}
            onChange={(e) => setSpendOverride(e.target.value)}
            placeholder="leave blank to use 0"
            className="w-full font-mono text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded px-3 py-1.5 text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
          />
        </div>
        <div>
          <label
            htmlFor="sim-agent-id"
            className="block text-mono-sm text-[var(--text-muted)] uppercase mb-2"
          >
            Agent ID (authoritative ledger)
          </label>
          <input
            id="sim-agent-id"
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            placeholder="optional; blank = simulator mode"
            className="w-full font-mono text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded px-3 py-1.5 text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
          />
        </div>
      </div>

      <button
        type="button"
        onClick={run}
        disabled={pending}
        className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium px-5 py-2 text-sm bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-40"
      >
        {pending ? "Evaluating…" : "Evaluate"}
      </button>

      {error && (
        <p className="text-sm text-[var(--status-stopped)] font-mono">{error}</p>
      )}

      {result && <PolicyEvaluationDisplay result={result} />}
    </div>
  );
}

function PolicyEvaluationDisplay({ result }: { result: EvaluateResult }) {
  const isAllow = result.verdict.kind === "allow";
  return (
    <div className="space-y-3 border-t border-[var(--border)] pt-4">
      <div className="flex items-center gap-2">
        <span
          className={`inline-flex items-center px-2 py-0.5 rounded-full border text-mono-sm uppercase ${
            isAllow
              ? "text-[var(--status-ok)] border-[var(--status-ok)]/20"
              : "text-[var(--status-stopped)] border-[var(--status-stopped)]/20"
          }`}
        >
          {isAllow ? "Allow" : "Deny"}
        </span>
        {!isAllow && result.verdict.kind === "deny" && (
          <span className="text-sm text-[var(--text-secondary)] font-mono">
            {result.verdict.check}: {result.verdict.reason}
          </span>
        )}
        {result.simulator && (
          <span className="inline-flex items-center px-2 py-0.5 rounded-full border text-mono-sm uppercase text-[var(--status-warning)] border-[var(--status-warning)]/20">
            simulator
          </span>
        )}
      </div>

      <p className="text-mono-sm text-[var(--text-muted)]">
        spend_total_usd: <span className="text-[var(--text-secondary)]">{result.spend_total_usd}</span>
      </p>

      {result.simulator_warning && (
        <p className="text-mono-sm text-[var(--status-warning)]">
          {result.simulator_warning}
        </p>
      )}

      <div>
        <p className="text-mono-sm text-[var(--text-muted)] uppercase mb-2">Trace</p>
        {result.trace.length === 0 ? (
          <p className="text-mono-sm text-[var(--text-muted)]">No checks ran.</p>
        ) : (
          <ul className="space-y-1">
            {result.trace.map((entry, i) => (
              <li key={i} className="font-mono text-sm flex items-baseline gap-2">
                <VerdictChip verdict={entry.verdict} />
                <span className="text-[var(--text-secondary)]">{entry.check}</span>
                {entry.verdict.kind === "deny" && (
                  <span className="text-[var(--text-muted)]">— {entry.verdict.reason}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function VerdictChip({ verdict }: { verdict: PolicyVerdict }) {
  const ok = verdict.kind === "allow";
  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-mono-sm ${
        ok
          ? "text-[var(--status-ok)] bg-[var(--status-ok)]/10"
          : "text-[var(--status-stopped)] bg-[var(--status-stopped)]/10"
      }`}
    >
      {ok ? "allow" : "deny"}
    </span>
  );
}
